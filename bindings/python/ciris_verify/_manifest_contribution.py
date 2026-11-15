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

23.0.0 adds the presenter path (CIRISVerify#315):
:func:`build_attestation_bundle_envelope` /
:func:`assemble_build_attestation_bundle` / :func:`verify_build_attestation_bundle`
for an occurrence presenting the build it runs.
"""

from __future__ import annotations

import ctypes
import json as _json
import platform as _platform
import threading as _threading
from pathlib import Path
from typing import Any, Optional

__all__ = [
    "verify_build_manifest_contribution",
    "build_attestation_bundle_envelope",
    "assemble_build_attestation_bundle",
    "verify_build_attestation_bundle",
]

_SYMBOLS = (
    "ciris_verify_build_manifest_contribution",
    "ciris_verify_build_attestation_bundle_envelope",
    "ciris_verify_build_attestation_bundle_assemble",
    "ciris_verify_build_attestation_bundle_verify",
)

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
                for symbol in _SYMBOLS:
                    _wire(getattr(lib, symbol))
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
        "must be built with the wheel (>= v23.0.0)."
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


def build_attestation_bundle_envelope(
    presents: str,
    presenter_key_id: str,
    manifest_contribution: Any,
    inclusion_proof: Optional[dict] = None,
    asserted_at: Optional[str] = None,
) -> dict:
    """The presenter's unsigned build-attestation envelope (CIRISVerify#315).

    Args:
        presents: ``"attestation:self_verify"`` or ``"attestation:agent_integrity"``.
        presenter_key_id: the presenting occurrence's federation key_id.
        manifest_contribution: the pipeline's ``build_manifest_contribution``
            object for the build the presenter runs.
        inclusion_proof: optional RFC 6962 inclusion proof for the manifest.
        asserted_at: RFC 3339; defaults to now.

    Returns:
        ``{"envelope": {...}, "signing_bytes_base64": "..."}``. Sign the bytes
        bound-hybrid (Ed25519, then ML-DSA-65 over ``bytes || ed25519_sig``)
        with the presenter's key and pass the result to
        :func:`assemble_build_attestation_bundle`.
    """
    req: dict = {
        "presents": presents,
        "presenter_key_id": presenter_key_id,
        "manifest_contribution": manifest_contribution,
    }
    if inclusion_proof is not None:
        req["inclusion_proof"] = inclusion_proof
    if asserted_at is not None:
        req["asserted_at"] = asserted_at
    return _call("ciris_verify_build_attestation_bundle_envelope", req)


def assemble_build_attestation_bundle(
    envelope: dict,
    ed25519_signature_base64: str,
    mldsa65_signature_base64: str,
    manifest_contribution: Any,
    inclusion_proof: Optional[dict] = None,
) -> dict:
    """Attach the evidence to a presenter-signed envelope.

    Returns the ``build_attestation_bundle`` object. Nothing is verified here;
    :func:`verify_build_attestation_bundle` is the check.
    """
    req: dict = {
        "signed": {
            "signed_envelope": envelope,
            "ed25519_signature_base64": ed25519_signature_base64,
            "mldsa65_signature_base64": mldsa65_signature_base64,
        },
        "manifest_contribution": manifest_contribution,
    }
    if inclusion_proof is not None:
        req["inclusion_proof"] = inclusion_proof
    return _call("ciris_verify_build_attestation_bundle_assemble", req)


def verify_build_attestation_bundle(
    bundle: Any,
    presenter_member: dict,
    pipeline_member: dict,
    blessing: dict,
    attester: Optional[str] = None,
) -> dict:
    """Verify a build-attestation bundle and return the verified build.

    Standing comes from ``pipeline_member`` + ``blessing``: your directory's
    answer, as for :func:`verify_build_manifest_contribution`.

    Returns:
        ``{"verified": True, "presenter_key_id", "presents", "transparency",
        "build": {"manifest_hash", "attestation_id", ...},
        "attestation_entries": [...]}`` or ``{"verified": False, "reason"}``.
    """
    req: dict = {
        "bundle": bundle,
        "presenter_member": presenter_member,
        "pipeline_member": pipeline_member,
        "blessing": blessing,
    }
    if attester is not None:
        req["attester"] = attester
    return _call("ciris_verify_build_attestation_bundle_verify", req)
