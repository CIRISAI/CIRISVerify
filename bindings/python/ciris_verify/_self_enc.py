"""Self content-encryption keypair derivation — Python binding (CIRISVerify#151).

Deterministically derives the two content-encryption keypairs (X25519 +
ML-KEM-768) from the Ed25519 base seed, over the FFI symbol
``ciris_verify_self_enc_derive``. Mirrors the wallet-derivation pattern: every
occurrence of a self FedID re-derives the **identical** keypair from the one
canonical seed, so the encryption identity travels for free with the FedID
backup/restore and is mathematically bound to the single identity.

The public halves are exactly what
``federation_identity_occurrences.pubkey_x25519_base64 /
pubkey_ml_kem_768_base64`` expect (CIRISPersist V069). The private halves stay
in-process — publish only the public fields.

    from ciris_verify import derive_self_enc
    keys = derive_self_enc(ed25519_seed)          # 32-byte seed
    occurrence.pubkey_x25519_base64     = keys.x25519_public_base64
    occurrence.pubkey_ml_kem_768_base64 = keys.ml_kem_768_ek_public_base64

**Scope:** self / single-principal only. Community DEKs keep independent keys +
epoch rotation for forward secrecy — do not derive there.
"""

from __future__ import annotations

import ctypes
import json as _json
import platform as _platform
import threading as _threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

__all__ = ["SelfEncKeys", "derive_self_enc"]

_lib: Optional[ctypes.CDLL] = None
_lib_lock = _threading.Lock()
_SUCCESS = 0


@dataclass(frozen=True)
class SelfEncKeys:
    """The derived self content-encryption keypairs (base64 fields).

    ``*_public`` / ``*_ek_public`` are the wire-published halves; ``*_secret`` /
    ``*_dk_seed`` are the enclave-held private halves (never publish).
    """

    x25519_secret_base64: str
    x25519_public_base64: str
    ml_kem_768_dk_seed_base64: str
    ml_kem_768_ek_public_base64: str


def _candidate_paths() -> list[str]:
    here = Path(__file__).resolve().parent
    system = _platform.system()
    names = {
        "Linux": ["libciris_verify_ffi.so", "libciris_verify.so"],
        "Darwin": ["libciris_verify_ffi.dylib", "libciris_verify.dylib"],
        "Windows": ["ciris_verify_ffi.dll", "ciris_verify.dll"],
    }.get(system, ["libciris_verify_ffi.so"])

    paths: list[str] = []
    for n in names:
        paths.append(str(here / n))
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
                fn = lib.ciris_verify_self_enc_derive
            except (OSError, AttributeError) as exc:
                last_err = exc
                continue
            fn.argtypes = [
                ctypes.c_char_p,  # input_json (UTF-8 bytes)
                ctypes.c_size_t,  # input_len
                ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)),  # result_out
                ctypes.POINTER(ctypes.c_size_t),  # result_len_out
            ]
            fn.restype = ctypes.c_int
            lib.ciris_verify_free.argtypes = [ctypes.c_void_p]
            lib.ciris_verify_free.restype = None
            _lib = lib
            return _lib
    raise RuntimeError(
        "ciris_verify_self_enc_derive not available — could not load the "
        f"CIRISVerify shared library (last error: {last_err}). "
        "The library must be built with the wheel (>= v8.3.0)."
    )


def derive_self_enc(ed25519_seed: bytes) -> SelfEncKeys:
    """Derive the self X25519 + ML-KEM-768 content-encryption keypairs.

    ``ed25519_seed`` is the 32-byte base seed. Returns a :class:`SelfEncKeys`
    whose fields are base64 strings, byte-identical to the Rust derivation
    (pinned by the ``self_enc`` golden vector).

    Raises ``ValueError`` if the seed is not exactly 32 bytes.
    """
    if len(ed25519_seed) != 32:
        raise ValueError(f"ed25519_seed must be 32 bytes, got {len(ed25519_seed)}")

    req = {"ed25519_seed": list(ed25519_seed)}
    input_bytes = _json.dumps(req).encode("utf-8")
    lib = _load_lib()
    out_ptr = ctypes.POINTER(ctypes.c_ubyte)()
    out_len = ctypes.c_size_t(0)
    rc = lib.ciris_verify_self_enc_derive(
        input_bytes,
        len(input_bytes),
        ctypes.byref(out_ptr),
        ctypes.byref(out_len),
    )
    if rc != _SUCCESS:
        raise ValueError(
            f"derive_self_enc: invalid request — the seed must be exactly 32 "
            f"bytes (FFI code {rc})"
        )
    n = out_len.value
    try:
        raw = ctypes.string_at(out_ptr, n)
    finally:
        if n != 0:
            lib.ciris_verify_free(ctypes.cast(out_ptr, ctypes.c_void_p))
    obj = _json.loads(raw.decode("utf-8"))
    return SelfEncKeys(
        x25519_secret_base64=obj["x25519_secret_base64"],
        x25519_public_base64=obj["x25519_public_base64"],
        ml_kem_768_dk_seed_base64=obj["ml_kem_768_dk_seed_base64"],
        ml_kem_768_ek_public_base64=obj["ml_kem_768_ek_public_base64"],
    )
