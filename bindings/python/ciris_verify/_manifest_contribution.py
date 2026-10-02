"""Build-manifest Contribution verification — Python binding
(CIRISVerify#25; reshaped in 19.0.0 for FSD-006 / CIRISVerify#299).

Exposes :func:`verify_build_manifest_contribution`, a thin wrapper over the FFI
symbol ``ciris_verify_build_manifest_contribution``, which calls
``ciris_verify_core::manifest_contribution``.

It checks everything a Contribution can prove about itself: the pipeline's
bound-hybrid signature, persist's signed ``row`` mirror, the
``provenance:build_manifest:{target}:v1`` dimension, ``infra:attest`` scope,
``asserted_at``, and that ``evidence_refs`` names the manifest blob.

**It does not decide whether the pipeline may attest builds.** That is one of
persist's two authorities over the caller's own directory: the capability walk
(``capability_roots_to_trusted_root(directory, node, pipeline, "infra:attest")``)
or the accord role (``is_infra_attest_effective(directory, pipeline)``, which is
how production pipelines are blessed). Pass its answer as ``blessing``; this
function checks only that the blessing names the pipeline that signed.

**Fail-closed:** a rejection is a successful call returning ``verified: False``
with a ``reason``, never an exception. Only a malformed request raises.
"""

from __future__ import annotations

import ctypes
import json as _json
import platform as _platform
import threading as _threading
from pathlib import Path
from typing import Any, Optional

__all__ = ["verify_build_manifest_contribution"]

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
                _wire(lib.ciris_verify_build_manifest_contribution)
            except (OSError, AttributeError) as exc:
                last_err = exc
                continue
            lib.ciris_verify_free.argtypes = [ctypes.c_void_p]
            lib.ciris_verify_free.restype = None
            _lib = lib
            return _lib
    raise RuntimeError(
        "manifest-contribution FFI symbol not available — could not load the "
        f"CIRISVerify shared library (last error: {last_err}). The library "
        "must be built with the wheel (>= v6.2.0)."
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


def verify_build_manifest_contribution(
    obj: Any,
    pipeline_member: dict,
    blessing: dict,
) -> dict:
    """Verify a build-manifest Contribution (FSD-006).

    Args:
        obj: the ``build_manifest_contribution`` object (a JSON-able
            ``SignedCegObject``).
        pipeline_member: the pipeline ``node``'s pinned pubkeys —
            ``{"member_id": ..., "ed25519_public_key_base64": ...,
            "mldsa65_public_key_base64": ...}``. Resolve it from your key
            directory, never from the object.
        blessing: your capability walk's answer for the pipeline —
            either ``{"pipeline_key_id": ..., "standing": "delegation" |
            "family_quorum", "root_key_id": ..., "grant_attestation_id": ...}``
            (persist's capability walk ``TrustedGrant``; reader-relative), or
            ``{"pipeline_key_id": ..., "standing": "accord_role"}`` (persist's
            ``is_infra_attest_effective`` — the accord ci-key ceremony's
            blessing, which is what production pipelines hold). Anything else
            raises ValueError.

    Returns:
        On success: ``{"verified": True, "attested_by", "standing",
        "conferred_by" (walk standings only), "grant_attestation_id" (walk
        standings only),
        "attestation_id", "asserted_at", "target",
        "build_id", "binary_hash", "binary_version", "manifest_hash",
        "manifest_size", "evidence_refs": [...]}``. On rejection:
        ``{"verified": False, "reason": "..."}`` naming the first failing step.

    Raises:
        ValueError: the request itself is malformed (a caller error, NOT a
            negative verdict).
        RuntimeError: the shared library / FFI symbols are unavailable.
    """
    return _call(
        "ciris_verify_build_manifest_contribution",
        {
            "object": obj,
            "pipeline_member": pipeline_member,
            "blessing": blessing,
        },
    )
