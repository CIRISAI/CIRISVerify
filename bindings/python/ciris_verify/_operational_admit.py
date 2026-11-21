"""Delegation scope split — Python binding (CIRISVerify#77).

Exposes :func:`verify_delegation_scope_split`, a thin wrapper over the FFI
symbol ``ciris_verify_delegation_scope_split``, which calls
``ciris_verify_core::operational_admit::verify_delegation_scope_split``: a
``node``-only delegate carrying any ``agency:*`` scope is rejected, and an
unknown scope fails closed. A pure evaluator — no I/O — and **fail-closed**: a
negative verdict is a successful call, never an exception.

``resolve_role_authority`` and ``verify_partner_record_quorum`` checked the
pair-signed ``organization`` / ``org_membership`` / ``partner_record`` rows,
which CC 3.3.9 retired; they were removed in 23.3.3.
"""

from __future__ import annotations

import ctypes
import json as _json
import platform as _platform
import threading as _threading
from pathlib import Path
from typing import Any, Optional

__all__ = ["verify_delegation_scope_split"]

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
                _wire(lib.ciris_verify_delegation_scope_split)
            except (OSError, AttributeError) as exc:
                last_err = exc
                continue
            lib.ciris_verify_free.argtypes = [ctypes.c_void_p]
            lib.ciris_verify_free.restype = None
            _lib = lib
            return _lib
    raise RuntimeError(
        "operational-admit FFI symbols not available — could not load the "
        f"CIRISVerify shared library (last error: {last_err}). The library "
        "must be built with the wheel (>= v5.1.0)."
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


def verify_delegation_scope_split(
    attested_identity_type: str,
    delegated_scope: list[str],
) -> dict:
    """Enforce the CEG §8.1.12.7.1 / §5.6.8.10 ``infra:*`` / ``agency:*``
    delegation scope split — the wire-checkable form of §1.3 "infrastructure
    must not have agency" (CIRISRegistry#83).

    Args:
        attested_identity_type: the caller-resolved §7.0.1 ``identity_type``
            SET (comma-joined) of the delegation's ``attested_key_id``. The
            delegate is a brain iff the set contains ``agent``.
        delegated_scope: the delegation's scopes. A ``node``-only delegate may
            carry only ``infra:*``; any ``agency:*`` (or legacy agency kind) is
            rejected, as is any unrecognized scope (fail-closed).

    Returns:
        ``{"ok": bool, "error": str?}``. Fail-closed: a violating delegation
        is ``ok: False`` with a reason, not an exception.

    Raises:
        ValueError: the request itself is malformed.
        RuntimeError: the shared library / FFI symbols are unavailable.
    """
    return _call(
        "ciris_verify_delegation_scope_split",
        {
            "attested_identity_type": attested_identity_type,
            "delegated_scope": delegated_scope,
        },
    )
