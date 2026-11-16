//! The executor: tasks, the run queue, timers and the event reactor.
//!
//! One [`Runtime`] per thread (the node is single-threaded, FSD §5.1; native
//! tests run nodes on several threads at once). It holds:
//!
//! * **tasks** in a slot vector with generation counters, polled from a FIFO
//!   run queue;
//! * **timers** in a `BTreeMap<(deadline_us, seq), Waker>`: ordered by
//!   deadline, ties broken by creation order, so firing order is
//!   deterministic (record and replay depend on that);
//! * **the reactor**: per-token state for `net` and `seal`, fed by
//!   [`Runtime::on_event`].
//!
//! Nothing here reads a clock or draws randomness except through
//! `ciris-host-abi`, so a run replays byte for byte.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::rc::{Rc, Weak};
use alloc::sync::Arc;
use alloc::task::Wake;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::fmt;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, Waker};
use std::sync::Mutex;

use ciris_host_abi::types::{CloseReason, FailReason, Phase};
use ciris_host_abi::{clock, wake, Event};

/// Rounds of the run queue one `tick` may make, whatever the clock says.
/// A round polls every task that was ready when it began; tasks woken
/// during a round run in the next. The cap guarantees `tick` returns even
/// under a clock that never advances (a scripted host), at the cost of a
/// self-waking task getting at most this many polls per tick.
pub const MAX_ROUNDS_PER_TICK: u32 = 64;

/// Lifecycle phases kept for [`crate::lifecycle::next`] when nobody reads
/// them; the oldest is dropped beyond this.
const LIFECYCLE_QUEUE_CAP: usize = 64;

type LocalFuture = Pin<Box<dyn Future<Output = ()>>>;
type TaskId = (usize, u32);

/// A task's waker. `Send + Sync` as the `Waker` contract requires, so a
/// waker handed to code that moves it across threads (a channel used from
/// a native test thread) stays sound: waking only pushes onto a mutexed
/// queue that the owning thread drains.
struct TaskWaker {
    id: TaskId,
    scheduled: AtomicBool,
    queue: Arc<Mutex<VecDeque<TaskId>>>,
}

impl Wake for TaskWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        if !self.scheduled.swap(true, Ordering::AcqRel) {
            lock(&self.queue).push_back(self.id);
        }
    }
}

fn lock(q: &Mutex<VecDeque<TaskId>>) -> std::sync::MutexGuard<'_, VecDeque<TaskId>> {
    // Single-threaded executor: a poisoned queue can only follow a panic
    // that already took the node down; keep the data.
    q.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

struct Slot {
    generation: u32,
    future: Option<LocalFuture>,
    waker: Option<(Arc<TaskWaker>, Waker)>,
    abort: Rc<Cell<bool>>,
}

/// What a token is for. The kind is the token's top byte, so a token in a
/// log or an event says what it names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum TokenKind {
    /// A dialled or accepted connection.
    Conn = 1,
    /// A listener.
    Listener = 2,
    /// An unconnected datagram socket.
    Datagram = 3,
    /// One seal operation.
    Seal = 4,
}

/// How a dial ended, as events reported it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Connect {
    Connected,
    Failed(FailReason),
}

/// Reactor state for one token.
#[derive(Default)]
pub(crate) struct IoEntry {
    pub(crate) read: Option<Waker>,
    pub(crate) write: Option<Waker>,
    /// Connect / seal completion waiter.
    pub(crate) done: Option<Waker>,
    pub(crate) connect: Option<Connect>,
    pub(crate) closed: Option<CloseReason>,
    pub(crate) listener_failed: Option<FailReason>,
    pub(crate) sealed: bool,
    /// The seal future was dropped before completion: take and discard the
    /// result when `sealed` arrives, so the host does not hold it forever.
    pub(crate) orphan: bool,
}

/// Which waker slot of an [`IoEntry`] a future parks in.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Interest {
    Read,
    Write,
    Done,
}

#[derive(Default)]
struct LifecycleState {
    current: Option<Phase>,
    queue: VecDeque<Phase>,
    waiter: Option<Waker>,
    clock_trusted: bool,
    clock_waiters: Vec<Waker>,
}

pub(crate) struct Inner {
    slots: RefCell<Vec<Slot>>,
    free: RefCell<Vec<usize>>,
    queue: Arc<Mutex<VecDeque<TaskId>>>,
    timers: RefCell<BTreeMap<(u64, u64), Waker>>,
    timer_seq: Cell<u64>,
    io: RefCell<BTreeMap<u64, IoEntry>>,
    token_seq: Cell<u64>,
    lifecycle: RefCell<LifecycleState>,
    live: Cell<usize>,
    polls: Cell<u64>,
}

std::thread_local! {
    static CURRENT: RefCell<Option<Runtime>> = const { RefCell::new(None) };
}

/// The cooperative executor of one node (FSD §5.1). Cheap to clone: all
/// clones are the same runtime.
///
/// The host loop drives it through the node's exports:
///
/// ```text
/// loop:
///     poll host I/O; deliver events with on-event   -> Runtime::on_event
///     deadline = tick(budget)                        -> Runtime::tick
///     sleep until deadline or host event
/// ```
#[derive(Clone)]
pub struct Runtime {
    inner: Rc<Inner>,
}

impl fmt::Debug for Runtime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Runtime")
            .field("tasks", &self.inner.live.get())
            .field("timers", &self.inner.timers.borrow().len())
            .field("tokens", &self.inner.io.borrow().len())
            .finish_non_exhaustive()
    }
}

impl Runtime {
    /// A fresh runtime, made the current one for this thread (replacing any
    /// previous one, whose tasks are dropped when its last handle goes).
    #[must_use]
    pub fn new() -> Self {
        let rt = Self {
            inner: Rc::new(Inner {
                slots: RefCell::new(Vec::new()),
                free: RefCell::new(Vec::new()),
                queue: Arc::new(Mutex::new(VecDeque::new())),
                timers: RefCell::new(BTreeMap::new()),
                timer_seq: Cell::new(0),
                io: RefCell::new(BTreeMap::new()),
                token_seq: Cell::new(0),
                lifecycle: RefCell::new(LifecycleState::default()),
                live: Cell::new(0),
                polls: Cell::new(0),
            }),
        };
        let old = CURRENT.with(|c| c.borrow_mut().replace(rt.clone()));
        drop(old);
        rt
    }

    /// This thread's runtime, created on first use.
    #[must_use]
    pub fn current() -> Self {
        if let Some(rt) = CURRENT.with(|c| c.borrow().clone()) {
            return rt;
        }
        Self::new()
    }

    /// Spawn `fut` on this runtime. See [`spawn`].
    pub fn spawn<F>(&self, fut: F) -> JoinHandle<F::Output>
    where
        F: Future + 'static,
        F::Output: 'static,
    {
        let state = Rc::new(RefCell::new(JoinState::Running(None)));
        let abort = Rc::new(Cell::new(false));
        let st = state.clone();
        let task: LocalFuture = Box::pin(async move {
            let out = fut.await;
            let waiter = {
                let mut s = st.borrow_mut();
                match core::mem::replace(&mut *s, JoinState::Finished(Some(out))) {
                    JoinState::Running(w) => w,
                    // Aborted while finishing: keep the abort.
                    other => {
                        *s = other;
                        None
                    },
                }
            };
            if let Some(w) = waiter {
                w.wake();
            }
        });
        let id = self.insert(task, abort.clone());
        JoinHandle {
            state,
            abort,
            rt: Rc::downgrade(&self.inner),
            id,
        }
    }

    fn insert(&self, future: LocalFuture, abort: Rc<Cell<bool>>) -> TaskId {
        let index = self.inner.free.borrow_mut().pop();
        let mut slots = self.inner.slots.borrow_mut();
        let index = index.unwrap_or_else(|| {
            slots.push(Slot {
                generation: 0,
                future: None,
                waker: None,
                abort: Rc::new(Cell::new(false)),
            });
            slots.len() - 1
        });
        let slot = &mut slots[index];
        let id = (index, slot.generation);
        let tw = Arc::new(TaskWaker {
            id,
            scheduled: AtomicBool::new(false),
            queue: self.inner.queue.clone(),
        });
        let waker = Waker::from(tw.clone());
        slot.future = Some(future);
        slot.abort = abort;
        slot.waker = Some((tw, waker.clone()));
        drop(slots);
        self.inner.live.set(self.inner.live.get() + 1);
        waker.wake();
        id
    }

    fn release(&self, index: usize) {
        let mut slots = self.inner.slots.borrow_mut();
        let slot = &mut slots[index];
        slot.generation = slot.generation.wrapping_add(1);
        slot.waker = None;
        drop(slots);
        self.inner.free.borrow_mut().push(index);
        self.inner.live.set(self.inner.live.get() - 1);
    }

    fn poll_task(&self, (index, generation): TaskId) {
        let taken = {
            let mut slots = self.inner.slots.borrow_mut();
            let Some(slot) = slots.get_mut(index) else {
                return;
            };
            if slot.generation != generation {
                return;
            }
            let Some(future) = slot.future.take() else {
                return;
            };
            let (tw, waker) = slot.waker.as_ref().expect("live slot has a waker");
            tw.scheduled.store(false, Ordering::Release);
            (future, waker.clone(), slot.abort.clone())
        };
        let (mut future, waker, abort) = taken;
        if abort.get() {
            self.release(index);
            drop(future);
            return;
        }
        self.inner.polls.set(self.inner.polls.get() + 1);
        let mut cx = Context::from_waker(&waker);
        let done = future.as_mut().poll(&mut cx).is_ready();
        if done || abort.get() {
            self.release(index);
            drop(future);
        } else {
            let mut slots = self.inner.slots.borrow_mut();
            slots[index].future = Some(future);
        }
    }

    fn pop_ready(&self) -> Option<TaskId> {
        lock(&self.inner.queue).pop_front()
    }

    fn ready_len(&self) -> usize {
        lock(&self.inner.queue).len()
    }

    /// Run ready tasks for at most `budget_us` of `clock.monotonic-us`
    /// (FSD §5.4), then return the next deadline and report it with
    /// `wake.next-deadline`.
    ///
    /// * The clock is read once at the start and once after every task
    ///   poll; the tick stops as soon as `budget_us` has elapsed. At least
    ///   one poll runs per tick, so a zero budget still makes progress.
    /// * Tasks run in rounds: each round polls the tasks that were ready
    ///   when it began, in wake order; tasks woken meanwhile (a yielding
    ///   task, a channel send) run in the next round. At most
    ///   [`MAX_ROUNDS_PER_TICK`] rounds per tick.
    /// * Timers whose deadline has passed fire at the start of the tick and
    ///   after every round.
    /// * Returns the current time if tasks are still ready (tick me again
    ///   now), else the earliest timer deadline, else `u64::MAX`.
    pub fn tick(&self, budget_us: u32) -> u64 {
        let start = clock::monotonic_us();
        let mut now = start;
        self.fire_timers(now);
        let mut first = true;
        'rounds: for _ in 0..MAX_ROUNDS_PER_TICK {
            let n = self.ready_len();
            if n == 0 {
                break;
            }
            for _ in 0..n {
                if !first && now.saturating_sub(start) >= u64::from(budget_us) {
                    break 'rounds;
                }
                let Some(id) = self.pop_ready() else {
                    break;
                };
                self.poll_task(id);
                first = false;
                now = clock::monotonic_us();
            }
            self.fire_timers(now);
        }
        self.fire_timers(now);
        let next = if self.ready_len() > 0 {
            now
        } else {
            self.next_timer().unwrap_or(u64::MAX)
        };
        wake::next_deadline(next);
        next
    }

    /// Route one host event to the futures waiting on its token (FSD §5.1).
    /// Events for unknown tokens (a connection already dropped) are
    /// ignored. `timer` needs no routing: timers fire on the next `tick`.
    pub fn on_event(&self, event: Event) {
        let mut wake: Vec<Waker> = Vec::new();
        let mut orphan_take = None;
        {
            let mut io = self.inner.io.borrow_mut();
            match event {
                Event::Readable(t) => {
                    if let Some(e) = io.get_mut(&t) {
                        wake.extend(e.read.take());
                    }
                },
                Event::Writable(t) => {
                    if let Some(e) = io.get_mut(&t) {
                        wake.extend(e.write.take());
                    }
                },
                Event::Connected(t) => {
                    if let Some(e) = io.get_mut(&t) {
                        e.connect = Some(Connect::Connected);
                        wake.extend(e.done.take());
                    }
                },
                Event::Failed(info) => {
                    if let Some(e) = io.get_mut(&info.token) {
                        e.connect = Some(Connect::Failed(info.reason));
                        wake.extend(e.done.take());
                        wake.extend(e.read.take());
                        wake.extend(e.write.take());
                    }
                },
                Event::ListenerFailed(info) => {
                    if let Some(e) = io.get_mut(&info.token) {
                        e.listener_failed = Some(info.reason);
                        wake.extend(e.read.take());
                    }
                },
                Event::Closed(info) => {
                    if let Some(e) = io.get_mut(&info.token) {
                        e.closed = Some(info.reason);
                        wake.extend(e.done.take());
                        wake.extend(e.read.take());
                        wake.extend(e.write.take());
                    }
                },
                Event::Sealed(t) => {
                    if let Some(e) = io.get_mut(&t) {
                        if e.orphan {
                            io.remove(&t);
                            orphan_take = Some(t);
                        } else {
                            e.sealed = true;
                            wake.extend(e.done.take());
                        }
                    }
                },
                Event::Lifecycle(p) => {
                    let mut l = self.inner.lifecycle.borrow_mut();
                    l.current = Some(p);
                    if l.queue.len() == LIFECYCLE_QUEUE_CAP {
                        l.queue.pop_front();
                    }
                    l.queue.push_back(p);
                    wake.extend(l.waiter.take());
                },
                Event::ClockTrusted => {
                    let mut l = self.inner.lifecycle.borrow_mut();
                    l.clock_trusted = true;
                    wake.append(&mut l.clock_waiters);
                },
                Event::Timer => {},
            }
        }
        if let Some(t) = orphan_take {
            // The future that started it is gone: collect and wipe.
            if let Ok(mut v) = ciris_host_abi::seal::take(t) {
                zeroize::Zeroize::zeroize(&mut v);
            }
        }
        for w in wake {
            w.wake();
        }
    }

    /// Live (spawned, not finished) tasks.
    #[must_use]
    pub fn tasks(&self) -> usize {
        self.inner.live.get()
    }

    /// Total task polls so far (for tests and metrics).
    #[must_use]
    pub fn polls(&self) -> u64 {
        self.inner.polls.get()
    }

    /// Pending timers.
    #[must_use]
    pub fn timers(&self) -> usize {
        self.inner.timers.borrow().len()
    }

    // ---- timers -------------------------------------------------------

    pub(crate) fn timer_insert(&self, deadline: u64, waker: Waker) -> (u64, u64) {
        let seq = self.inner.timer_seq.get();
        self.inner.timer_seq.set(seq + 1);
        self.inner
            .timers
            .borrow_mut()
            .insert((deadline, seq), waker);
        (deadline, seq)
    }

    /// Refresh the waker of a pending timer; `false` if it already fired.
    pub(crate) fn timer_update(&self, key: (u64, u64), waker: &Waker) -> bool {
        match self.inner.timers.borrow_mut().get_mut(&key) {
            Some(w) => {
                if !w.will_wake(waker) {
                    w.clone_from(waker);
                }
                true
            },
            None => false,
        }
    }

    pub(crate) fn timer_remove(&self, key: (u64, u64)) {
        self.inner.timers.borrow_mut().remove(&key);
    }

    fn next_timer(&self) -> Option<u64> {
        self.inner.timers.borrow().keys().next().map(|k| k.0)
    }

    fn fire_timers(&self, now: u64) {
        let fired: Vec<Waker> = {
            let mut t = self.inner.timers.borrow_mut();
            let later = t.split_off(&(now.saturating_add(1), 0));
            core::mem::replace(&mut *t, later).into_values().collect()
        };
        for w in fired {
            w.wake();
        }
    }

    // ---- reactor ------------------------------------------------------

    /// A fresh token of `kind`, registered with the reactor. Tokens are
    /// `kind << 56 | n` with `n` counting from 1 per runtime and never
    /// reused, so they are unique per node, deterministic under replay,
    /// and name their kind in a log. Token 0 is never issued.
    pub(crate) fn alloc_token(&self, kind: TokenKind) -> u64 {
        let n = self.inner.token_seq.get() + 1;
        self.inner.token_seq.set(n);
        let token = (u64::from(kind as u8) << 56) | (n & ((1 << 56) - 1));
        self.inner.io.borrow_mut().insert(token, IoEntry::default());
        token
    }

    pub(crate) fn unregister(&self, token: u64) {
        self.inner.io.borrow_mut().remove(&token);
    }

    pub(crate) fn park(&self, token: u64, interest: Interest, waker: &Waker) {
        if let Some(e) = self.inner.io.borrow_mut().get_mut(&token) {
            let slot = match interest {
                Interest::Read => &mut e.read,
                Interest::Write => &mut e.write,
                Interest::Done => &mut e.done,
            };
            match slot {
                Some(w) if w.will_wake(waker) => {},
                _ => *slot = Some(waker.clone()),
            }
        }
    }

    pub(crate) fn with_entry<R>(&self, token: u64, f: impl FnOnce(&mut IoEntry) -> R) -> Option<R> {
        self.inner.io.borrow_mut().get_mut(&token).map(f)
    }

    // ---- lifecycle ----------------------------------------------------

    pub(crate) fn lifecycle_current(&self) -> Option<Phase> {
        self.inner.lifecycle.borrow().current
    }

    pub(crate) fn lifecycle_poll(&self, cx: &mut Context<'_>) -> Poll<Phase> {
        let mut l = self.inner.lifecycle.borrow_mut();
        if let Some(p) = l.queue.pop_front() {
            return Poll::Ready(p);
        }
        l.waiter = Some(cx.waker().clone());
        Poll::Pending
    }

    pub(crate) fn clock_trusted(&self) -> bool {
        self.inner.lifecycle.borrow().clock_trusted
    }

    pub(crate) fn clock_trusted_poll(&self, cx: &mut Context<'_>) -> Poll<()> {
        let mut l = self.inner.lifecycle.borrow_mut();
        if l.clock_trusted {
            return Poll::Ready(());
        }
        l.clock_waiters.push(cx.waker().clone());
        Poll::Pending
    }
}

impl Default for Runtime {
    fn default() -> Self {
        Self::current()
    }
}

/// Spawn `fut` on this thread's runtime. No `Send` bound: the node is one
/// thread (FSD §5.2, "no `Send` bound needed, none removed"). The task
/// first runs on the next [`Runtime::tick`]. Dropping the [`JoinHandle`]
/// detaches the task; it keeps running.
pub fn spawn<F>(fut: F) -> JoinHandle<F::Output>
where
    F: Future + 'static,
    F::Output: 'static,
{
    Runtime::current().spawn(fut)
}

/// Why a [`JoinHandle`] yielded no value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum JoinError {
    /// [`JoinHandle::abort`] cancelled the task before it finished.
    Cancelled,
}

impl JoinError {
    /// Whether the task was cancelled (tokio's spelling).
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled)
    }
}

impl fmt::Display for JoinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("task was cancelled")
    }
}

impl core::error::Error for JoinError {}

enum JoinState<T> {
    Running(Option<Waker>),
    Finished(Option<T>),
    Aborted,
}

/// A spawned task's handle; itself a future yielding the task's output.
/// Shapes match tokio's: `Output = Result<T, JoinError>`, `abort()`,
/// `is_finished()`.
pub struct JoinHandle<T> {
    state: Rc<RefCell<JoinState<T>>>,
    abort: Rc<Cell<bool>>,
    rt: Weak<Inner>,
    id: TaskId,
}

impl<T> fmt::Debug for JoinHandle<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JoinHandle")
            .field("task", &self.id)
            .field("finished", &self.is_finished())
            .finish()
    }
}

impl<T> JoinHandle<T> {
    /// Cancel the task. If it has not finished, its future is dropped
    /// before its next poll (at the latest on the next tick) and awaiting
    /// this handle yields [`JoinError::Cancelled`]. No effect on a finished
    /// task.
    pub fn abort(&self) {
        let waiter = {
            let mut s = self.state.borrow_mut();
            match &mut *s {
                JoinState::Running(w) => {
                    let w = w.take();
                    *s = JoinState::Aborted;
                    w
                },
                _ => return,
            }
        };
        self.abort.set(true);
        // Schedule the task so the executor drops it promptly.
        if let Some(inner) = self.rt.upgrade() {
            let slots = inner.slots.borrow();
            if let Some(slot) = slots.get(self.id.0) {
                if slot.generation == self.id.1 {
                    if let Some((_, w)) = &slot.waker {
                        w.wake_by_ref();
                    }
                }
            }
        }
        if let Some(w) = waiter {
            w.wake();
        }
    }

    /// Whether the task finished or was aborted.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        !matches!(*self.state.borrow(), JoinState::Running(_))
    }
}

impl<T> Future for JoinHandle<T> {
    type Output = Result<T, JoinError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut s = self.state.borrow_mut();
        match &mut *s {
            JoinState::Running(w) => {
                match w {
                    Some(old) if old.will_wake(cx.waker()) => {},
                    _ => *w = Some(cx.waker().clone()),
                }
                Poll::Pending
            },
            JoinState::Finished(v) => Poll::Ready(Ok(v
                .take()
                .expect("JoinHandle polled after it returned the output"))),
            JoinState::Aborted => Poll::Ready(Err(JoinError::Cancelled)),
        }
    }
}

/// Yield to the executor once: the task is re-queued behind every task
/// that is already ready.
pub fn yield_now() -> YieldNow {
    YieldNow { yielded: false }
}

/// The future of [`yield_now`].
#[derive(Debug)]
#[must_use = "futures do nothing unless awaited"]
pub struct YieldNow {
    yielded: bool,
}

impl Future for YieldNow {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.yielded {
            return Poll::Ready(());
        }
        self.yielded = true;
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

/// Run blocking work. There is one thread (FSD §5.2: `spawn_blocking`
/// maps to inline), so `f` runs inline, now, and its value is returned.
/// Long work must page itself and yield between pages (FSD §5.4).
pub async fn blocking<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    f()
}

/// `tokio::task::spawn_blocking`'s shape, for a mechanical swap: `f` runs
/// inline NOW (FSD §5.2), and the returned handle is already finished.
pub fn spawn_blocking<F, R>(f: F) -> JoinHandle<R>
where
    F: FnOnce() -> R,
    R: 'static,
{
    let out = f();
    JoinHandle {
        state: Rc::new(RefCell::new(JoinState::Finished(Some(out)))),
        abort: Rc::new(Cell::new(false)),
        rt: Weak::new(),
        id: (usize::MAX, 0),
    }
}
