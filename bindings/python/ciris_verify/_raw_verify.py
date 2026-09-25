"""Raw Ed25519 / P-256 signature verification (CIRISVerify#207 item 1).

The wheel exposed ``sign_ed25519`` and no verify counterpart, so a consumer
that signed through verify could not verify through it — CIRISAgent's
``audit/signing_protocol.py`` falls back to the ``cryptography`` library.

Both functions return a dict carrying ``valid`` **and** the acceptance rule or
encoding that produced it, because in both cases the choice is real and a
caller that gates on the answer should be able to assert on how it was reached.
"""

from __future__ import annotations

import ctypes
import json as _json
import platform as _platform
import threading as _threading
from pathlib import Path
from typing import Any, Optional

_SUCCESS = 0
_lib: Optional[ctypes.CDLL] = None
_lib_lock = _threading.Lock()


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
                fn = lib.ciris_verify_verify_ed25519
            except (OSError, AttributeError) as exc:
                last_err = exc
                continue
            fn.argtypes = [
                ctypes.c_char_p,  # config_json (UTF-8 bytes)
                ctypes.POINTER(ctypes.c_void_p),  # result_out (char**)
            ]
            fn.restype = ctypes.c_int
            lib.ciris_verify_free_string.argtypes = [ctypes.c_void_p]
            lib.ciris_verify_free_string.restype = None
            _lib = lib
            return _lib
    raise RuntimeError(
        "ciris_verify_verify_ed25519 not available — could not load "
        f"the CIRISVerify shared library (last error: {last_err}). "
        "The library must be built with the wheel (>= 17.0.0)."
    )


def _call(symbol: str, config: dict[str, Any]) -> dict[str, Any]:
    """One JSON-in/JSON-out call, so both entry points free identically."""
    lib = _load_lib()
    fn = getattr(lib, symbol)
    fn.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
    fn.restype = ctypes.c_int
    cfg_bytes = _json.dumps(config).encode("utf-8")
    out = ctypes.c_void_p()
    rc = fn(cfg_bytes, ctypes.byref(out))
    if rc != _SUCCESS:
        raise RuntimeError(f"{symbol}: FFI error code {rc}")
    if not out.value:
        raise RuntimeError(f"{symbol}: FFI returned no result")
    try:
        raw = ctypes.cast(out, ctypes.c_char_p).value
    finally:
        lib.ciris_verify_free_string(out)
    result = _json.loads(raw.decode("utf-8")) if raw else {}
    if not result.get("ok"):
        raise ValueError(result.get("error", f"{symbol} failed"))
    return result


def verify_ed25519(
    public_key: bytes,
    message: bytes,
    signature: bytes,
    *,
    strict: bool = True,
) -> dict[str, Any]:
    """Verify an Ed25519 signature. Strict by default — keep it that way.

    Permissive (cofactorless) Ed25519 verification accepts a **universal
    forgery**: with the identity point as the public key, the single signature
    ``(R = identity, s = 0)`` verifies against *any* message, with no private
    key in existence. ``strict=False`` exists only to reproduce another
    implementation's acceptance set deliberately; never to decide anything.

    Returns a dict with ``valid`` and ``rule`` (``"strict"`` / ``"permissive"``).

    Raises:
        ValueError: if the key or signature is malformed.
    """
    return _call(
        "ciris_verify_verify_ed25519",
        {
            "public_key_hex": public_key.hex(),
            "message_hex": message.hex(),
            "signature_hex": signature.hex(),
            "strict": strict,
        },
    )


def verify_p256(
    public_key: bytes,
    message: bytes,
    signature: bytes,
    *,
    encoding: str,
) -> dict[str, Any]:
    """Verify an ECDSA P-256 signature over SHA-256 of ``message``.

    ``public_key`` is SEC1 (``0x04 || x || y``). ``encoding`` is **required**:
    ``"fixed"`` for the 64-byte ``r || s`` form, ``"der"`` for the ASN.1 form
    that WebAuthn / FIDO2 ``ES256`` assertions carry.

    It is not inferred. Sniffing looks unambiguous and is not — a DER signature
    with a 29-byte ``r`` and ``s`` is exactly 64 bytes, and a fixed-form
    signature whose ``r`` starts ``0x30`` carries the DER tag — and guessing
    wrong reports a genuinely valid signature as invalid, which on a
    verification path reads as tampering.

    Returns a dict with ``valid`` and the ``encoding`` that was applied.

    Raises:
        ValueError: if the key or signature is malformed, or ``encoding`` is
            not one of the two accepted values.
    """
    return _call(
        "ciris_verify_verify_p256",
        {
            "public_key_hex": public_key.hex(),
            "message_hex": message.hex(),
            "signature_hex": signature.hex(),
            "encoding": encoding,
        },
    )
