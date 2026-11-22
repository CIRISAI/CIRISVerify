"""HUMANITY_ACCORD halt latch status — Python binding (CIRISVerify#305).

Exposes :func:`accord_latch_status`, a thin wrapper over the FFI symbol
``ciris_verify_accord_latch_status``: the act gate's question, is this node
paused, over a latch a node persisted from
``ciris_verify_core::accord_halt_latch::HaltLatch::apply_forward`` (edition-2
rows read by ``edition2::accord_halt``).

``verify_accord_invocation`` and ``accord_latch_apply`` read the earlier,
pair-signed invocation form and were removed in 23.3.3.
"""

from __future__ import annotations

import ctypes
import json as _json
import platform as _platform
import threading as _threading
from pathlib import Path
from typing import Any, Optional

__all__ = ["accord_latch_status"]

_lib: Optional[ctypes.CDLL] = None
_lib_lock = _threading.Lock()
_SUCCESS = 0


def _candidate_paths() -> list[str]:
    here = Path(__file__).resolve().parent
    system = _platform.system()
    names = {
        "Linux": ["libciris_verify_ffi.so", "libciris_verify.so"],
        "Darwin": ["libciris_verify_ffi.dylib", "libciris_verify.dylib"],
        "Windows": ["ciris_verify_ffi.dll", "ciris_verify.dll"],
    }.get(system, ["libciris_verify_ffi.so"])
    paths: list[str] = [str(here / n) for n in names]
    try:
        from .client import DEFAULT_BINARY_PATHS  # type: ignore

        paths.extend(DEFAULT_BINARY_PATHS.get(system, []))
    except Exception:  # pragma: no cover - defensive
        pass
    return paths


def _wire(fn: Any) -> None:
    fn.argtypes = [
        ctypes.c_char_p,  # input_json (UTF-8 bytes)
        ctypes.c_size_t,  # input_len
        ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)),  # result_out
        ctypes.POINTER(ctypes.c_size_t),  # result_len_out
    ]
    fn.restype = ctypes.c_int


def _load_lib() -> ctypes.CDLL:
    global _lib
    if _lib is not None:
        return _lib
    with _lib_lock:
        if _lib is not None:
            return _lib
        last_err: Optional[Exception] = None
        for path in _candidate_paths():
            if not Path(path).exists():
                continue
            try:
                lib = ctypes.CDLL(path)
                _wire(lib.ciris_verify_accord_latch_status)
            except (OSError, AttributeError) as exc:
                last_err = exc
                continue
            lib.ciris_verify_free.argtypes = [ctypes.c_void_p]
            lib.ciris_verify_free.restype = None
            _lib = lib
            return _lib
    raise RuntimeError(
        "accord latch FFI symbol not available — could not load the "
        f"CIRISVerify shared library (last error: {last_err}). The library "
        "must be built with the wheel (>= v19.1.0)."
    )


def _call(symbol: str, request: dict) -> dict:
    lib = _load_lib()
    fn = getattr(lib, symbol)
    body = _json.dumps(request, ensure_ascii=False).encode("utf-8")
    out_ptr = ctypes.POINTER(ctypes.c_ubyte)()
    out_len = ctypes.c_size_t(0)
    rc = fn(body, len(body), ctypes.byref(out_ptr), ctypes.byref(out_len))
    if rc != _SUCCESS:
        raise ValueError(
            f"{symbol}: malformed request (FFI code {rc}) — this is a caller "
            "error, distinct from a fail-closed negative verdict"
        )
    n = out_len.value
    if n == 0:
        return {}
    try:
        raw = ctypes.string_at(out_ptr, n)
    finally:
        lib.ciris_verify_free(ctypes.cast(out_ptr, ctypes.c_void_p))
    return _json.loads(raw)


def accord_latch_status(latch: Optional[dict], halt_fuse_secs: Optional[int] = None) -> dict:
    """The act gate's question: is this node paused?

    Call it before every effectful act (CC 4.2.1.1). ``latch`` is the state
    the node persisted (``None`` when clear); ``halt_fuse_secs`` is the bundle
    in force's (omit for the 86400 default).

    The fuse is elapsed time (FSD-007 §3): verify reads the platform's
    monotonic clock itself and counts the time since the latch's checkpoint
    (none across a reboot), so no wall-clock setting can shorten a halt. The
    returned ``latch`` is the advanced state: persist it in place of the one
    passed in. Returns ``{"paused", "halt_id", "confirmed", "elapsed_ms",
    "remaining_ms", "signal", "latch"}``; ``signal`` is
    ``"monotonic_regressed"`` when the clock read lower than at the checkpoint
    (nothing was counted), else ``None``. A latch of the 23.4 shape is
    refused (``ValueError``); re-apply the held accord rows instead.
    """
    req: dict = {"latch": latch}
    if halt_fuse_secs is not None:
        req["halt_fuse_secs"] = halt_fuse_secs
    return _call("ciris_verify_accord_latch_status", req)
