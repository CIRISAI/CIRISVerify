//! What a reader acts on where a trust root's lineage has more than one tip
//! (CC 3.2 T6, *Two successors of one bundle*; CC 2.6.1.11, *A bundle that
//! joins tips*; CC 2.7.8, the guarded fold).
//!
//! A port of CIRISKernel's reference model (`models/trust_root/root.py`,
//! branch `root-fold` 272fcd6), replayed against its `root_reader.json`. It
//! reads bundles already read one by one: each [`RootBundle`] states whether
//! its own count concluded and which keys' statements verified. This module
//! judges nothing about one bundle; it answers what holds across several.
//!
//! - Two later bundles on one bundle are both tips, and no rule picks one. A
//!   bundle's **regime** is its charter without `recovery_commitments`, as
//!   one value. Tips of one regime fold (a key or a seat one tip adds is in
//!   where no other tip removed it beside the addition, and the bundle that
//!   adds it is counted over the holders the fold already seats). Tips whose
//!   regimes differ do not fold: the holders and seats common to them.
//! - Two joins of the same predecessors under different regimes, neither in
//!   the other's past, are contested (`genesis_join_contested`): neither
//!   stands, and a reader that acknowledged them keeps the tips they tried to
//!   join, until a bundle names every one of them.
//! - Two recoveries of one seat, neither in the other's past, are contested
//!   the same way: the seat stays as it was.
//! - A bundle whose every counted voice also signed a bundle it is behind is
//!   self-forked, and is void where the holders who built only on the other
//!   side outnumber those only on its side. A bundle built on a void one is
//!   void.
//! - In force is per reader: its anchor names its first bundle, and the
//!   bundles in force are the newest it acknowledged, in the order it
//!   acknowledged them. With none acknowledged, the anchor's bundle.
//!
//! Keys, seats and bundles are named by 32-byte ids. A holder is its key: a
//! recovery seats another key for the same seat, and `owners` says which
//! holder a key speaks for.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use super::Digest32;

/// The detail a contested join is reported under (a state, not Invalid).
pub const GENESIS_JOIN_CONTESTED: &str = "genesis_join_contested";

type Id = Digest32;
type Set = BTreeSet<Id>;

/// One bundle of a lineage, as its own read left it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootBundle {
    /// The object id.
    pub id: Id,
    /// The predecessors it names: `refs.prev`, then `refs.further_prev`.
    pub prev: Vec<Id>,
    /// `version`.
    pub version: u32,
    /// The keys it seats as holders.
    pub holders: Set,
    /// Its seats.
    pub seats: Set,
    /// Its regime: the charter's deterministic encoding without
    /// `recovery_commitments`. Compared for equality only.
    pub regime: Vec<u8>,
    /// The keys whose statements over it verified (with the payload's
    /// `iat`), before any revocation bound is read.
    pub voices: Set,
    /// A recovery: the holder key it replaces and the key it seats.
    pub recovers: Option<(Id, Id)>,
    /// Its own count concluded (its predecessors' included).
    pub concluded: bool,
}

/// A holder key's revocation, as the caller read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRevocation {
    /// The key.
    pub key: Id,
    /// The last bundle its statements are good on; `None`: no bound, and the
    /// key leaves the live holders.
    pub bound: Option<Id>,
}

/// A reader's anchor, resolved against the lineage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReaderAnchor {
    /// The object id of one first bundle.
    Bundle(Id),
    /// The holder keys of the first bundle.
    Holders(Set),
}

/// One reader: its anchor, and the bundles it acknowledged in the order it
/// acknowledged them (its owner's `trust:accepts` edges, each naming a bundle
/// in `attached_head_digest`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reader {
    /// The anchor; `None` roots on nothing.
    pub anchor: Option<ReaderAnchor>,
    /// The acknowledged bundles, in order.
    pub acks: Vec<Id>,
}

/// What is in force for one reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InForce {
    /// The bundles in force: the newest the reader acknowledged, none in
    /// another's past; with none acknowledged, its first bundle.
    pub heads: Vec<Id>,
    /// The holder keys to act on.
    pub holders: Set,
    /// The seats to act on.
    pub seats: Set,
    /// With several heads: did they fold (one regime), or are these only
    /// what the heads have in common (regimes differ)?
    pub folded: bool,
    /// The contested bundles the reader acknowledged: joins of one set of
    /// predecessors under different regimes, or recoveries of one seat
    /// (reported as a fork is; `genesis_join_contested` for a join).
    pub contested: Vec<Id>,
}

/// The bundles of a lineage the reader holds, read together.
#[derive(Debug)]
pub struct Lineage<'a> {
    by: BTreeMap<Id, &'a RootBundle>,
    revokes: &'a [KeyRevocation],
    owners: &'a BTreeMap<Id, Id>,
    past: BTreeMap<Id, Set>,
    void: Set,
    contest: Set,
}

impl<'a> Lineage<'a> {
    /// Read `bundles` together. `owners` maps a key to the holder it speaks
    /// for where that is not itself (a recovery key, and the key a recovery
    /// seats, speak for the holder recovered).
    #[must_use]
    pub fn new(
        bundles: &'a [RootBundle],
        revokes: &'a [KeyRevocation],
        owners: &'a BTreeMap<Id, Id>,
    ) -> Self {
        let by: BTreeMap<Id, &RootBundle> = bundles.iter().map(|b| (b.id, b)).collect();
        let mut past = BTreeMap::new();
        for id in by.keys() {
            fill_past(&by, *id, &mut past, &mut BTreeSet::new());
        }
        let mut l = Self {
            by,
            revokes,
            owners,
            past,
            void: Set::new(),
            contest: Set::new(),
        };
        let (void, contest) = l.read_void();
        l.void = void;
        l.contest = contest;
        l
    }

    // ---- the lineage

    fn past(&self, i: &Id) -> &Set {
        static EMPTY: Set = Set::new();
        self.past.get(i).unwrap_or(&EMPTY)
    }

    fn in_line(&self, x: &Id, of: &Id) -> bool {
        x == of || self.past(of).contains(x)
    }

    fn line(&self, i: &Id) -> Set {
        let mut s = self.past(i).clone();
        s.insert(*i);
        s
    }

    fn owner(&self, k: &Id) -> Id {
        let mut k = *k;
        // A short chain: a recovered key's holder may itself be recovered.
        for _ in 0..64 {
            match self.owners.get(&k) {
                Some(o) if *o != k => k = *o,
                _ => break,
            }
        }
        k
    }

    fn own<'k>(&self, ks: impl IntoIterator<Item = &'k Id>) -> Set {
        ks.into_iter().map(|k| self.owner(k)).collect()
    }

    // ---- the count

    fn live(&self, holders: &Set) -> Set {
        holders
            .iter()
            .filter(|k| {
                !self
                    .revokes
                    .iter()
                    .any(|r| r.key == **k && r.bound.is_none())
            })
            .copied()
            .collect()
    }

    /// The keys whose statement on `b` counts: verified, and not voided by a
    /// revocation bound.
    #[must_use]
    pub fn voices(&self, b: &RootBundle) -> Set {
        b.voices
            .iter()
            .filter(|k| {
                let mut bounds = self
                    .revokes
                    .iter()
                    .filter(|r| r.key == **k)
                    .filter_map(|r| r.bound)
                    .peekable();
                bounds.peek().is_none()
                    || bounds.any(|x| self.by.contains_key(&x) && self.in_line(&b.id, &x))
            })
            .copied()
            .collect()
    }

    /// The keys a recovery replaced across the branches of `prevs`.
    fn retired(&self, prevs: &[Id]) -> Set {
        let mut out = Set::new();
        for p in prevs {
            for x in self.line(p) {
                if let Some((old, _)) = self.by.get(&x).and_then(|q| q.recovers) {
                    out.insert(old);
                }
            }
        }
        out
    }

    /// `b`'s count on `voices`: a strict majority of each named
    /// predecessor's live holders, less (on a join) the keys a recovery
    /// replaced across its branches; `within` restricts the base to the
    /// holders a fold already seats.
    #[must_use]
    pub fn meets(&self, b: &RootBundle, voices: &Set, within: Option<&Set>) -> bool {
        if b.prev.is_empty() {
            return false;
        }
        let gone = if b.prev.len() >= 2 {
            self.retired(&b.prev)
        } else {
            Set::new()
        };
        b.prev.iter().all(|p| {
            let Some(pb) = self.by.get(p) else {
                return false;
            };
            let base: Set = self
                .live(&pb.holders)
                .into_iter()
                .filter(|k| !gone.contains(k))
                .filter(|k| within.is_none_or(|w| w.contains(k)))
                .collect();
            2 * voices.intersection(&base).count() > base.len()
        })
    }

    /// The live holders whose statements on `b` are voices.
    fn base(&self, b: &RootBundle) -> Set {
        let mut all = Set::new();
        for p in &b.prev {
            if let Some(pb) = self.by.get(p) {
                all.extend(pb.holders.iter().copied());
            }
        }
        let mut out = self.live(&all);
        if b.prev.len() >= 2 {
            for k in self.retired(&b.prev) {
                out.remove(&k);
            }
        }
        out
    }

    fn concluded(&self) -> Vec<&'a RootBundle> {
        self.by.values().copied().filter(|b| b.concluded).collect()
    }

    /// A join contested by a rival: a concluded join of the same
    /// predecessors under another regime, neither in the other's past.
    fn contested_join(&self, b: &RootBundle) -> bool {
        if b.prev.len() < 2 || !b.concluded {
            return false;
        }
        let named: BTreeSet<&Id> = b.prev.iter().collect();
        self.by.values().any(|x| {
            x.id != b.id
                && x.concluded
                && x.prev.len() >= 2
                && x.prev.iter().collect::<BTreeSet<_>>() == named
                && x.regime != b.regime
                && !self.past(&b.id).contains(&x.id)
                && !self.past(&x.id).contains(&b.id)
        })
    }

    // ---- self-forks and contests

    /// `b` is behind `c`: every bundle `b` extends is strictly in the past of
    /// a bundle `c` extends, and `b` is not in `c`'s past.
    fn behind(&self, b: &RootBundle, c: &RootBundle) -> bool {
        if c.id == b.id || self.past(&c.id).contains(&b.id) || b.prev.is_empty() {
            return false;
        }
        b.prev
            .iter()
            .all(|p| !c.prev.contains(p) && c.prev.iter().any(|cp| self.in_line(p, cp)))
    }

    /// `b`'s counted voices, as the holders they speak for.
    fn voices_of(&self, b: &RootBundle) -> Set {
        if let Some((old, _)) = b.recovers {
            return self.own([&old]);
        }
        let v = self.voices(b);
        if b.prev.is_empty() {
            self.own(v.intersection(&b.holders))
        } else {
            self.own(v.intersection(&self.base(b)))
        }
    }

    #[allow(clippy::too_many_lines)]
    fn read_void(&self) -> (Set, Set) {
        let cs = self.concluded();
        let mut tv = Set::new();
        let mut contest = Set::new();

        // Self-forked bundles, void by the holders on each side.
        let forked = |b: &RootBundle| {
            if b.prev.is_empty() {
                return false;
            }
            let v = self.voices_of(b);
            !v.is_empty()
                && v.iter().all(|k| {
                    cs.iter()
                        .any(|c| self.own(&self.voices(c)).contains(k) && self.behind(b, c))
                })
        };
        for b in cs.iter().copied().filter(|b| forked(b)) {
            let i = b.id;
            let mem = self.own(&self.base(b));
            let beh: Vec<&RootBundle> = cs.iter().copied().filter(|c| self.behind(b, c)).collect();
            let first_line = self.line(&b.prev[0]);
            let mut chain = Set::new();
            let mut todo: Vec<Id> = beh.iter().map(|c| c.id).collect();
            while let Some(x) = todo.pop() {
                if chain.contains(&x) || first_line.contains(&x) {
                    continue;
                }
                let Some(xb) = self.by.get(&x) else { continue };
                chain.insert(x);
                todo.extend(xb.prev.iter().copied());
            }
            let past_has_beh =
                |c: &RootBundle| beh.iter().any(|x| self.past(&c.id).contains(&x.id));
            let mut km = Set::new();
            let mut ko = Set::new();
            for c in &cs {
                let on_mine = c.id == i || self.past(&c.id).contains(&i);
                if on_mine && !past_has_beh(c) {
                    km.extend(self.voices_of(c).intersection(&mem).copied());
                }
                if c.id != i
                    && !self.past(&c.id).contains(&i)
                    && (chain.contains(&c.id) || past_has_beh(c))
                {
                    ko.extend(self.voices_of(c).intersection(&mem).copied());
                }
            }
            if ko.difference(&km).count() > km.difference(&ko).count() {
                tv.insert(i);
            }
        }
        let close = |tv: &mut Set| loop {
            let before = tv.len();
            for c in &cs {
                if !tv.contains(&c.id) && c.prev.iter().any(|p| tv.contains(p)) {
                    tv.insert(c.id);
                }
            }
            if tv.len() == before {
                break;
            }
        };
        close(&mut tv);

        // Two recoveries of one seat, neither in the other's past.
        let recs: Vec<&RootBundle> = cs
            .iter()
            .copied()
            .filter(|c| c.recovers.is_some() && !tv.contains(&c.id))
            .collect();
        let seat = |c: &RootBundle| (c.prev[0], c.recovers.map(|r| r.0));
        let mut groups: BTreeMap<(Id, Option<Id>), Set> = BTreeMap::new();
        for c in &recs {
            let rivals: Vec<Id> = recs
                .iter()
                .filter(|x| {
                    x.id != c.id
                        && seat(x) == seat(c)
                        && !self.past(&c.id).contains(&x.id)
                        && !self.past(&x.id).contains(&c.id)
                })
                .map(|x| x.id)
                .collect();
            if !rivals.is_empty() {
                let g = groups.entry(seat(c)).or_default();
                g.extend(rivals);
                g.insert(c.id);
            }
        }
        for ((pv, _), mut g) in groups {
            let named_by_one = cs
                .iter()
                .any(|c| !tv.contains(&c.id) && g.is_subset(self.past(&c.id)));
            if named_by_one {
                continue;
            }
            let mem = self
                .by
                .get(&pv)
                .map(|p| self.own(&self.live(&p.holders)))
                .unwrap_or_default();
            let mut side: BTreeMap<Id, Set> = BTreeMap::new();
            for r in &g {
                let mut s = Set::new();
                for x in &cs {
                    let line = self.line(&x.id);
                    if line.contains(r) && !g.iter().any(|q| q != r && line.contains(q)) {
                        s.extend(self.voices_of(x).intersection(&mem).copied());
                    }
                }
                side.insert(*r, s);
            }
            let only = |r: &Id| {
                side[r]
                    .iter()
                    .filter(|k| !g.iter().any(|q| q != r && side[q].contains(*k)))
                    .count()
            };
            let top = g.iter().map(only).max().unwrap_or(0);
            let lose: Set = g.iter().filter(|r| only(r) < top).copied().collect();
            tv.extend(lose.iter().copied());
            g.retain(|r| !lose.contains(r));
            if g.len() < 2 {
                continue;
            }
            for c in &cs {
                let line = self.line(&c.id);
                if g.iter().any(|x| line.contains(x)) && !g.is_subset(&line) {
                    tv.insert(c.id);
                }
                if g.contains(&c.id) {
                    contest.insert(c.id);
                }
            }
        }
        close(&mut tv);

        // A forked join: joins of the same predecessors under different
        // regimes, until a bundle names every one of them.
        let mut jgroups: BTreeMap<BTreeSet<Id>, Set> = BTreeMap::new();
        for c in &cs {
            if self.contested_join(c) {
                jgroups
                    .entry(c.prev.iter().copied().collect())
                    .or_default()
                    .insert(c.id);
            }
        }
        loop {
            let mut changed = false;
            for g in jgroups.values() {
                let settled = cs
                    .iter()
                    .any(|c| !tv.contains(&c.id) && g.is_subset(self.past(&c.id)));
                if settled {
                    continue;
                }
                for c in &cs {
                    let line = self.line(&c.id);
                    if !tv.contains(&c.id)
                        && g.iter().any(|x| line.contains(x))
                        && (g.contains(&c.id) || !g.is_subset(&line))
                    {
                        tv.insert(c.id);
                        changed = true;
                        if g.contains(&c.id) {
                            contest.insert(c.id);
                        }
                    }
                }
            }
            if !changed {
                break;
            }
        }
        close(&mut tv);
        (tv, contest)
    }

    /// The bundles void by a self-fork or a contest.
    #[must_use]
    pub fn void(&self) -> &Set {
        &self.void
    }

    /// The contested bundles: joins that do not fold with a rival, and rival
    /// recoveries of one seat.
    #[must_use]
    pub fn contested(&self) -> &Set {
        &self.contest
    }

    /// The bundles that concluded and are not void, sorted.
    #[must_use]
    pub fn valid(&self) -> Vec<Id> {
        self.by
            .values()
            .filter(|b| b.concluded && !self.void.contains(&b.id))
            .map(|b| b.id)
            .collect()
    }

    // ---- for one reader

    /// The reader's first bundle (`genesis_bundle_not_anchored` otherwise;
    /// under a holders anchor, also where two first bundles match it).
    #[must_use]
    pub fn first(&self, rd: &Reader) -> Option<Id> {
        let anchor = rd.anchor.as_ref()?;
        let mut firsts = self.valid().into_iter().filter(|i| {
            let b = self.by[i];
            b.prev.is_empty()
                && match anchor {
                    ReaderAnchor::Bundle(a) => a == i,
                    ReaderAnchor::Holders(h) => *h == b.holders,
                }
        });
        let first = firsts.next()?;
        // Two first bundles the anchor's holders both signed are a fork of
        // the genesis: the reader roots on neither (CC 2.6.1.11).
        firsts.next().is_none().then_some(first)
    }

    /// The bundles void for a reader that acknowledged `acked`: one behind a
    /// bundle it acknowledged and not on its line, and every bundle built on
    /// one.
    fn reader_void(&self, acked: &[Id], valid: &[Id]) -> Set {
        let mut on = Set::new();
        for a in acked {
            on.extend(self.line(a));
        }
        let mut out: Set = valid
            .iter()
            .filter(|i| {
                !on.contains(*i) && acked.iter().any(|a| self.behind(self.by[*i], self.by[a]))
            })
            .copied()
            .collect();
        loop {
            let before = out.len();
            for i in valid {
                if !out.contains(i)
                    && !on.contains(i)
                    && self.by[i].prev.iter().any(|p| out.contains(p))
                {
                    out.insert(*i);
                }
            }
            if out.len() == before {
                break;
            }
        }
        out
    }

    /// The reader's own line (its acknowledgements in order, each taken
    /// unless void for it by those before) and the bundles void for it.
    fn reader_line(&self, rd: &Reader) -> (Vec<Id>, Set) {
        let valid = self.valid();
        let mut acc: Vec<Id> = Vec::new();
        for a in &rd.acks {
            if valid.contains(a) && !self.reader_void(&acc, &valid).contains(a) {
                acc.push(*a);
            }
        }
        let rv = self.reader_void(&acc, &valid);
        (acc, rv)
    }

    /// The bundles in force for the reader, sorted; `None` where it roots on
    /// nothing.
    #[must_use]
    pub fn heads(&self, rd: &Reader) -> Option<Vec<Id>> {
        let first = self.first(rd)?;
        let (line, rv) = self.reader_line(rd);
        let held: Set = self
            .valid()
            .into_iter()
            .filter(|i| (*i == first || self.past(i).contains(&first)) && !rv.contains(i))
            .collect();
        let mut acked: Set = line.into_iter().filter(|i| held.contains(i)).collect();
        // A contested bundle the reader acknowledged leaves it at the
        // bundles that one extends, and so on down.
        let mut todo: Vec<Id> = rd
            .acks
            .iter()
            .filter(|i| self.contest.contains(*i))
            .copied()
            .collect();
        let mut seen = Set::new();
        while let Some(x) = todo.pop() {
            if !seen.insert(x) {
                continue;
            }
            let Some(xb) = self.by.get(&x) else { continue };
            for p in &xb.prev {
                if held.contains(p) {
                    acked.insert(*p);
                } else if self.contest.contains(p) {
                    todo.push(*p);
                }
            }
        }
        if acked.is_empty() {
            return Some(alloc::vec![first]);
        }
        Some(
            acked
                .iter()
                .filter(|i| !acked.iter().any(|j| self.past(j).contains(*i)))
                .copied()
                .collect(),
        )
    }

    /// What the reader acts on; `None` where it roots on nothing.
    #[must_use]
    pub fn in_force(&self, rd: &Reader) -> Option<InForce> {
        let heads = self.heads(rd)?;
        let (holders, seats, folded) = self.fold(&heads);
        Some(InForce {
            contested: rd
                .acks
                .iter()
                .filter(|i| self.contest.contains(*i))
                .copied()
                .collect::<Set>()
                .into_iter()
                .collect(),
            heads,
            holders,
            seats,
            folded,
        })
    }

    // ---- the fold

    /// The holders and seats at `tips`, and whether they folded: one tip,
    /// its own; several of one regime, the guarded fold; several whose
    /// regimes differ, what is common to them.
    #[must_use]
    pub fn fold(&self, tips: &[Id]) -> (Set, Set, bool) {
        let bs: Vec<&RootBundle> = tips
            .iter()
            .filter_map(|t| self.by.get(t).copied())
            .collect();
        let Some((first, rest)) = bs.split_first() else {
            return (Set::new(), Set::new(), false);
        };
        if rest.is_empty() {
            return (first.holders.clone(), first.seats.clone(), true);
        }
        let common = |f: fn(&RootBundle) -> &Set| -> Set {
            f(first)
                .iter()
                .filter(|k| rest.iter().all(|b| f(b).contains(*k)))
                .copied()
                .collect()
        };
        let ch = common(|b| &b.holders);
        let cs = common(|b| &b.seats);
        if rest.iter().any(|b| b.regime != first.regime) {
            return (ch, cs, false);
        }
        let holders = self.fold_field(&bs, Field::Holders, &ch, None);
        let seats = self.fold_field(&bs, Field::Seats, &cs, Some(&holders));
        (holders, seats, true)
    }

    fn field(b: &RootBundle, f: Field) -> &Set {
        match f {
            Field::Holders => &b.holders,
            Field::Seats => &b.seats,
        }
    }

    /// Do any of `b`'s held predecessors carry `k`?
    fn prev_has(&self, b: &RootBundle, k: &Id, f: Field) -> (bool, bool) {
        let mut any = false;
        let mut all = true;
        for p in &b.prev {
            let has = self
                .by
                .get(p)
                .is_some_and(|pb| Self::field(pb, f).contains(k));
            any |= has;
            all &= has;
        }
        (any, all)
    }

    /// The bundles on `t`'s line that add `k` (there, and in none of their
    /// predecessors').
    fn adding(&self, t: &Id, k: &Id, f: Field) -> Vec<&'a RootBundle> {
        self.line(t)
            .iter()
            .filter_map(|i| self.by.get(i).copied())
            .filter(|b| Self::field(b, f).contains(k) && !self.prev_has(b, k, f).0)
            .collect()
    }

    /// The bundles on `t`'s line that remove `k`.
    fn removals(&self, t: &Id, k: &Id, f: Field) -> Vec<&'a RootBundle> {
        self.line(t)
            .iter()
            .filter_map(|i| self.by.get(i).copied())
            .filter(|b| {
                !b.prev.is_empty() && !Self::field(b, f).contains(k) && self.prev_has(b, k, f).0
            })
            .collect()
    }

    fn fold_field(
        &self,
        tips: &[&RootBundle],
        f: Field,
        common: &Set,
        holders: Option<&Set>,
    ) -> Set {
        let mut union = Set::new();
        for t in tips {
            union.extend(Self::field(t, f).iter().copied());
        }
        let survives = |k: &Id| {
            let at = |t: &RootBundle| Self::field(t, f).contains(k);
            for t in tips.iter().filter(|t| at(t)) {
                let a = self
                    .adding(&t.id, k, f)
                    .into_iter()
                    .max_by_key(|b| (b.version, b.id));
                let in_past_of_a =
                    |r: &RootBundle| a.is_some_and(|a| self.past(&a.id).contains(&r.id));
                let mut ok = true;
                for t2 in tips.iter().filter(|t2| !at(t2)) {
                    // Removed beside the addition.
                    if self.removals(&t2.id, k, f).iter().any(|r| !in_past_of_a(r)) {
                        ok = false;
                        break;
                    }
                    // A recovery is a rotation of an existing seat, not an
                    // addition: the key it seats is in only where the
                    // holder's seat itself is in.
                    let rot = a
                        .filter(|_| f == Field::Holders)
                        .and_then(|a| a.recovers)
                        .filter(|r| r.1 == *k);
                    if let Some((old, _)) = rot {
                        let out = self
                            .removals(&t2.id, &old, f)
                            .iter()
                            .any(|r| r.recovers.is_none_or(|rr| rr.0 != old) && !in_past_of_a(r));
                        if out {
                            ok = false;
                            break;
                        }
                    }
                }
                if ok {
                    return true;
                }
            }
            false
        };
        let cand: Vec<Id> = union
            .difference(common)
            .filter(|k| survives(k))
            .copied()
            .collect();
        let mut folded = common.clone();
        let mut base = holders.cloned().unwrap_or_else(|| common.clone());
        loop {
            let mut changed = false;
            for k in &cand {
                if folded.contains(k) {
                    continue;
                }
                let mut ok = true;
                for t in tips.iter().filter(|t| Self::field(t, f).contains(k)) {
                    for b in self.adding(&t.id, k, f) {
                        if b.prev.is_empty() || b.recovers.is_some_and(|r| r.1 == *k) {
                            continue;
                        }
                        if !self.meets(b, &self.voices(b), Some(&base)) {
                            ok = false;
                        }
                    }
                }
                if ok {
                    folded.insert(*k);
                    changed = true;
                    if holders.is_none() {
                        base.insert(*k);
                    }
                }
            }
            if !changed {
                break;
            }
        }
        folded
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Field {
    Holders,
    Seats,
}

fn fill_past(
    by: &BTreeMap<Id, &RootBundle>,
    i: Id,
    past: &mut BTreeMap<Id, Set>,
    visiting: &mut Set,
) {
    if past.contains_key(&i) || !visiting.insert(i) {
        return;
    }
    let mut out = Set::new();
    if let Some(b) = by.get(&i) {
        for p in &b.prev {
            if by.contains_key(p) {
                fill_past(by, *p, past, visiting);
                out.insert(*p);
                if let Some(pp) = past.get(p) {
                    out.extend(pp.iter().copied());
                }
            }
        }
    }
    past.insert(i, out);
}
