"""EVM tx-fields signing, keccak256 and EIP-55 checksums (CIRISVerify#207 item 2).

Why this module exists: ``sign_evm_transaction`` takes only a pre-computed
32-byte hash, so a Python caller had to rebuild RLP + keccak256 itself — in
CIRISAgent's case with a three-way fallback across ``pysha3`` /
``pycryptodome`` / ``eth_hash``, for real-money transactions. The bytes a key
commits to were produced by whichever library happened to import.

These bind the Rust entry points that do RLP and keccak **inside** the crate
that holds the key, so there is one implementation of the preimage.

The signing entry point itself needs the wallet handle, so it lives on the
client as ``CIRISVerify.sign_evm_transaction_fields``; these two need no key
and stay module-level.
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
                fn = lib.ciris_verify_keccak256
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
        "ciris_verify_keccak256 not available — could not load "
        f"the CIRISVerify shared library (last error: {last_err}). "
        "The library must be built with the wheel (>= 16.3.0)."
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


def keccak256(data: bytes) -> bytes:
    """keccak256 of ``data`` — the EVM hash, from the crate that signs.

    This is **Keccak-256, not FIPS-202 SHA3-256**: they differ in padding, and
    a caller reaching for "sha3" in most languages gets the wrong one and a
    wrong address.
    """
    r = _call("ciris_verify_keccak256", {"data_hex": data.hex()})
    return bytes.fromhex(r["keccak256_hex"])


def checksum_address(address: bytes | str) -> str:
    """EIP-55 checksum an **arbitrary** 20-byte address.

    The pubkey-only helper could not reach the address that matters most on a
    transfer — the recipient. Accepts 20 raw bytes or a hex string.
    """
    hexs = address.hex() if isinstance(address, bytes) else address
    return _call("ciris_verify_checksum_address", {"address_hex": hexs})["checksummed"]
