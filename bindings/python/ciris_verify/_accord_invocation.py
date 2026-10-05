"""HUMANITY_ACCORD invocation verification — Python binding
(CIRISVerify#305, v19.1.0+).

Exposes :func:`verify_accord_invocation`, a thin wrapper over the FFI symbol
``ciris_verify_accord_invocation_verify``, which calls
``ciris_verify_core::humanity_accord::verify_invocation``. There is one blessed
implementation of the CC 4.2.1.1 canonical bytes, the hybrid signature check and
the per-kind thresholds; a consumer reaches it rather than re-deriving any of
them in Python.

The thresholds are the steward's (CIRISConstitution#146, CC 4.2.1.1 rc7):
**one** holder for ``constitutional``, ``drill`` and ``notify``; a **strict
majority of the standing roster** for ``lifecycle:active``. A constitutional
halt fires on receipt of one valid row.

**Fail-closed:** a rejection is a successful call returning
``verified: False`` with a ``reason``; only a malformed request raises.
"""

from __future__ import annotations

import ctypes
import json as _json
import platform as _platform
import threading as _threading
from pathlib import Path
from typing import Any, Optional

__all__ = ["verify_accord_invocation", "accord_latch_apply", "accord_latch_status"]

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
                _wire(lib.ciris_verify_accord_invocation_verify)
                _wire(lib.ciris_verify_accord_latch_apply)
                _wire(lib.ciris_verify_accord_latch_status)
            except (OSError, AttributeError) as exc:
                last_err = exc
                continue
            lib.ciris_verify_free.argtypes = [ctypes.c_void_p]
            lib.ciris_verify_free.restype = None
            _lib = lib
            return _lib
    raise RuntimeError(
        "accord-invocation verify FFI symbol not available — could not load the "
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


def verify_accord_invocation(invocation: dict, roster: list, signatures: list) -> dict:
    """Verify an accord invocation against your pinned holder roster.

    Args:
        invocation: the invocation dict (``invocation_kind``, ``invocation_id``,
            ``nonce``, ``asserted_at``, ``valid_until``, ``payload_sha256``, and
            ``resumes_halt_id`` for ``lifecycle:active`` only).
        roster: the accord holders from **your own pinned bundle** —
            ``[{"member_id", "ed25519_public_key_base64",
            "mldsa65_public_key_base64"}, ...]``. Never a roster taken from the
            object you are verifying: that lets its producer choose who counts.
        signatures: ``[{"member_id", "ed25519_signature_base64",
            "mldsa65_signature_base64"}, ...]``.

    Returns:
        ``{"verified": bool, "invocation_kind", "invocation_id", "valid",
        "required"}``, plus ``"reason"`` when not verified.

    Not done here, and yours to do (CC 4.2.1.1 / 4.2.1.3): refuse a duplicate
    ``invocation_id`` within ``valid_until``; latch a verified constitutional
    halt idempotently and check the latch before every effectful act; clear it
    only by a verified ``lifecycle:active`` whose ``resumes_halt_id`` names the
    halt actually in force.

    Raises:
        ValueError: the request itself is malformed (a caller error, NOT a
            negative verdict).
        RuntimeError: the shared library / FFI symbol is unavailable.
    """
    return _call(
        "ciris_verify_accord_invocation_verify",
        {"invocation": invocation, "roster": roster, "signatures": signatures},
    )


def accord_latch_apply(
    latch: Optional[dict],
    invocation: dict,
    roster: list,
    signatures: list,
    now: str,
    halt_fuse_secs: Optional[int] = None,
) -> dict:
    """Verify an accord row and apply it to the node's halt latch, in one call.

    The CC 4.2.1.1 / 4.2.1.3 rules (CIRISConstitution#146 as amended): one
    holder's ``constitutional`` row pauses agents; the pause lapses
    ``halt_fuse_secs`` (default 86400) after **this node's receipt** unless a
    majority ``lifecycle:confirmed`` naming it arrives first; a majority
    ``lifecycle:active`` naming it ends it, confirmed or not. Verification and
    latching are one call, so an unverified row can never touch the latch.

    Args:
        latch: the state returned by the previous call (``None`` when clear).
            Persist it: the latch must survive a restart.
        invocation, roster, signatures: as for :func:`verify_accord_invocation`;
            ``roster`` is your own pinned roster.
        now: this node's clock, RFC 3339 — the receipt time for a new halt.
        halt_fuse_secs: the charter's value; omit for the 86400 default.

    Returns:
        ``{"outcome": "paused"|"confirmed"|"resumed"|"unchanged"|"refused",
        "reason"?, "latch", "paused", "halt_id", "confirmed", "lapses_at"}``.
        A refused row returns ``latch`` exactly as given.
    """
    req: dict = {
        "latch": latch,
        "invocation": invocation,
        "roster": roster,
        "signatures": signatures,
        "now": now,
    }
    if halt_fuse_secs is not None:
        req["halt_fuse_secs"] = halt_fuse_secs
    return _call("ciris_verify_accord_latch_apply", req)


def accord_latch_status(latch: Optional[dict], now: str, halt_fuse_secs: Optional[int] = None) -> dict:
    """The act gate's question: is this node paused at ``now``?

    Call it before every effectful act (CC 4.2.1.1). Returns
    ``{"paused", "halt_id", "confirmed", "lapses_at", "latch"}``.
    """
    req: dict = {"latch": latch, "now": now}
    if halt_fuse_secs is not None:
        req["halt_fuse_secs"] = halt_fuse_secs
    return _call("ciris_verify_accord_latch_status", req)
