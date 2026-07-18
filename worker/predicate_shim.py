"""cffi binding for the C predicate shim (bazooka_predicate).

Worker-facing: exposes predicate(d_bytes, pubkey_bytes) -> bool, running the
tool's own secp256k1 pubkey check instead of a slow pure-Python EC multiply.
"""
import os

from cffi import FFI

_ffi = FFI()
_ffi.cdef("int bazooka_predicate(const unsigned char *d, const unsigned char *pubkey);")

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
# Search order: explicit override, CMake build tree, standalone build_shim.sh output.
_CANDIDATES = [
    os.environ.get("BAZOOKA_PREDICATE_SO", ""),
    os.path.join(_REPO, "build", "libbazooka_predicate.so"),
    os.path.join(_HERE, "build", "libbazooka_predicate.so"),
]
_SO = next((p for p in _CANDIDATES if p and os.path.exists(p)), None)
if _SO is None:
    raise OSError(
        "libbazooka_predicate.so not found. Build it via CMake (target "
        "bazooka_predicate) or worker/build_shim.sh, or set BAZOOKA_PREDICATE_SO."
    )
_lib = _ffi.dlopen(_SO)


def predicate(d_bytes, pubkey_bytes):
    """True iff d*G == pubkey. d_bytes: 32-byte big-endian scalar;
    pubkey_bytes: 33-byte compressed SEC1 point."""
    if len(d_bytes) != 32:
        raise ValueError("d must be 32 bytes")
    if len(pubkey_bytes) != 33:
        raise ValueError("pubkey must be 33 bytes (compressed SEC1)")
    return _lib.bazooka_predicate(d_bytes, pubkey_bytes) == 1
