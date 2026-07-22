"""CC 2.3.2.1 canonical-hash subject codec (CIRISVerify#201).

An attestation subject is either a **key** (a ``key_id``) or a **content
hash**. A bare 64-hex string is format-indistinguishable from a ``key_id``, so
CC 2.3.2.1 requires the tagged form ``canonical:sha256:<64 lower hex>`` and
mandates that bare hex be **rejected**.

This module reaches the one blessed Rust implementation
(``ciris_verify_core::canonical_subject``) rather than re-deriving the tag, so
producers, admission gates and conformance all agree byte-for-byte.
"""

from __future__ import annotations

import ctypes
import json as _json
import platform as _platform
import threading as _threading
from pathlib import Path
from typing import Any, Optional

__all__ = [
    "canonical_subject",
    "canonical_subject_from_triple",
    "parse_canonical_subject",
    "CanonicalSubjectError",
]

_lib: Optional[ctypes.CDLL] = None
_lib_lock = _threading.Lock()
_SUCCESS = 0


class CanonicalSubjectError(ValueError):
    """A subject was not an admissible ``canonical:sha256:<hex>`` subject.

    ``kind`` is the machine-readable classification: ``"bare_hex"`` for the
    security-relevant ambiguous case (indistinguishable from a ``key_id``), or
    ``"other"``.
    """

    def __init__(self, message: str, kind: str) -> None:
        super().__init__(message)
        self.kind = kind


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
                fn = lib.ciris_verify_canonical_subject
                fn.argtypes = [
                    ctypes.c_char_p,
                    ctypes.c_size_t,
                    ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)),
                    ctypes.POINTER(ctypes.c_size_t),
                ]
                fn.restype = ctypes.c_int
            except (OSError, AttributeError) as exc:
                last_err = exc
                continue
            lib.ciris_verify_free.argtypes = [ctypes.c_void_p]
            lib.ciris_verify_free.restype = None
            _lib = lib
            return _lib
    raise RuntimeError(
        "canonical-subject FFI symbol not available — could not load the "
        f"CIRISVerify shared library (last error: {last_err}). Requires >= v10.6.0."
    )


def _call(request: dict) -> Any:
    lib = _load_lib()
    payload = _json.dumps(request).encode("utf-8")
    out = ctypes.POINTER(ctypes.c_ubyte)()
    out_len = ctypes.c_size_t()
    rc = lib.ciris_verify_canonical_subject(
        payload, len(payload), ctypes.byref(out), ctypes.byref(out_len)
    )
    if rc != _SUCCESS:
        raise ValueError(f"canonical-subject FFI rejected the request (code {rc})")
    try:
        raw = bytes(bytearray(out[: out_len.value]))
    finally:
        lib.ciris_verify_free(ctypes.cast(out, ctypes.c_void_p))
    return _json.loads(raw.decode("utf-8"))


def canonical_subject(platform: str, entity_kind: str, id: str) -> str:  # noqa: A002
    """Build ``canonical:sha256:<hex>`` for ``{platform}:{entity_kind}:{id}``.

    ``platform`` and ``entity_kind`` must not contain ``:``.
    """
    result = _call(
        {"op": "encode", "platform": platform, "entity_kind": entity_kind, "id": id}
    )
    if not result.get("ok"):
        raise CanonicalSubjectError(result.get("error", "encode failed"), "other")
    return result["subject"]


def canonical_subject_from_triple(triple: str) -> str:
    """Build the subject from a joined ``{platform}:{entity_kind}:{id}`` string.

    Splits on the first two colons only, so ``id`` may itself contain colons.
    """
    result = _call({"op": "encode_triple", "triple": triple})
    if not result.get("ok"):
        raise CanonicalSubjectError(result.get("error", "encode failed"), "other")
    return result["subject"]


def parse_canonical_subject(subject: str) -> bytes:
    """Validate a canonical-hash subject and return its 32-byte digest.

    Accepts **only** ``canonical:sha256:<64 lowercase hex>``. Raises
    :class:`CanonicalSubjectError` otherwise — with ``kind == "bare_hex"`` for
    an untagged 64-hex subject, which CC 2.3.2.1 requires be rejected because
    it is indistinguishable from a ``key_id``.
    """
    result = _call({"op": "parse", "subject": subject})
    if not result.get("ok"):
        raise CanonicalSubjectError(
            result.get("error", "not a canonical subject"), result.get("kind", "other")
        )
    return bytes.fromhex(result["digest_hex"])
