"""CC 5.1 per-stream call DEK — Python binding (CIRISVerify#308).

The epoch DEK of a ``live_stream`` is derived from the group's MLS exporter
secret, bound to one stream and one epoch by an HKDF step::

    exporter_secret = MLS-Exporter("ciris-stream-dek/v1", "", 32)
    DEK = HKDF-SHA256(ikm=exporter_secret, salt="",
                      info=b"ciris-stream-dek/v1" || stream_id_utf8 || u64_be(epoch),
                      L=32)

The caller supplies ``exporter_secret``: it MUST be exactly
``MLS-Exporter("ciris-stream-dek/v1", "", 32)`` (label
:data:`STREAM_DEK_LABEL`, empty context, length 32) of the group at ``epoch``.
Verify does no MLS. ``stream_id`` is, normatively, the lowercase hex of the
32-byte stream-id digest, 64 characters, for every stream kind (CC 5.3.3.1;
:func:`stream_id_hex`). CIRISEdge's A/V spelling ``av-{64 lowercase hex}``
(:func:`av_stream_id`) is a recorded divergence, accepted for compatibility.
The two spellings of one digest derive different DEKs.

The bytes come from the one Rust impl over the FFI symbol
``ciris_verify_stream_dek_derive``; there is no second implementation.

    from ciris_verify import stream_dek, stream_id_hex
    dek = stream_dek(exporter_secret, stream_id_hex(stream_id_digest), epoch)  # 32 bytes
"""

from __future__ import annotations

import ctypes
import json as _json
import re as _re
import threading as _threading
from pathlib import Path
from typing import Optional

from ._epoch_key import _candidate_paths

__all__ = ["STREAM_DEK_LABEL", "av_stream_id", "stream_dek", "stream_id_hex"]

#: The one CC 5.1 label: the MLS exporter label and the HKDF ``info`` tag.
STREAM_DEK_LABEL = "ciris-stream-dek/v1"

# The normative bare form (CC 5.3.3.1), or edge's av- form (compatibility).
_STREAM_ID_RE = _re.compile(r"(?:av-)?[0-9a-f]{64}")
_lib: Optional[ctypes.CDLL] = None
_lib_lock = _threading.Lock()
_SUCCESS = 0
_INVALID_ARGUMENT = -1


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
                fn = lib.ciris_verify_stream_dek_derive
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
        "ciris_verify_stream_dek_derive not available — could not load the "
        f"CIRISVerify shared library (last error: {last_err}). "
        "The library must be built with the wheel (>= v23.0.0)."
    )


def stream_id_hex(digest: bytes) -> str:
    """The normative stream id (CC 5.3.3.1): the lowercase hex of a 32-byte
    stream-id digest, 64 characters, for every stream kind."""
    if len(digest) != 32:
        raise ValueError(f"digest must be 32 bytes, got {len(digest)}")
    return digest.hex()


def av_stream_id(header_stream_id: bytes) -> str:
    """CIRISEdge's divergent A/V spelling ``av-{lowercase hex}`` of a 32-byte
    header stream id.

    Accepted for compatibility; the normative form is :func:`stream_id_hex`
    (CC 5.3.3.1). The two spellings derive different DEKs.
    """
    return "av-" + stream_id_hex(header_stream_id)


def stream_dek(exporter_secret: bytes, stream_id: str, epoch: int) -> bytes:
    """CC 5.1 — the 32-byte DEK of ``stream_id`` at ``epoch``.

    ``exporter_secret`` is ``MLS-Exporter("ciris-stream-dek/v1", "", 32)`` of the
    group at ``epoch``. Raises ``ValueError`` on a secret that is not 32 bytes,
    an epoch outside ``u64``, or a ``stream_id`` that is neither 64 lowercase
    hex (CC 5.3.3.1) nor ``av-{64 lowercase hex}`` (edge's form).
    """
    if len(exporter_secret) != 32:
        raise ValueError(f"exporter_secret must be 32 bytes, got {len(exporter_secret)}")
    if epoch < 0 or epoch > 0xFFFF_FFFF_FFFF_FFFF:
        raise ValueError("epoch must fit in a u64")
    if not _STREAM_ID_RE.fullmatch(stream_id):
        raise ValueError(
            "stream_id must be 64 lowercase hex digits (or edge's av- + 64 lowercase hex)"
        )
    input_bytes = _json.dumps(
        {"exporter_secret": list(exporter_secret), "stream_id": stream_id, "epoch": epoch}
    ).encode("utf-8")
    lib = _load_lib()
    out_ptr = ctypes.POINTER(ctypes.c_ubyte)()
    out_len = ctypes.c_size_t(0)
    rc = lib.ciris_verify_stream_dek_derive(
        input_bytes,
        len(input_bytes),
        ctypes.byref(out_ptr),
        ctypes.byref(out_len),
    )
    if rc != _SUCCESS:
        what = "malformed stream_id" if rc == _INVALID_ARGUMENT else "invalid request"
        raise ValueError(f"stream_dek: {what} (FFI code {rc})")
    n = out_len.value
    try:
        result = ctypes.string_at(out_ptr, n)
    finally:
        if n != 0:
            lib.ciris_verify_free(ctypes.cast(out_ptr, ctypes.c_void_p))
    return result
