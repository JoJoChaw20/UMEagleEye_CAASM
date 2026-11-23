"""Ed25519 signature verification (RFC 8032, section 5.1.7), in pure Python.

Only verifying: the agent checks that an update package was signed with the project's key
(keys.py). Signing happens on the build machine with the `cryptography` library
(packaging/sign_package.py). Kept here so the Windows build needs no native crypto library; a
verification takes a few milliseconds. Checked against RFC 8032's test vectors and against
signatures made by `cryptography` (tests/test_update.py).
"""

from __future__ import annotations

import hashlib
from typing import Optional

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493       # order of the base point
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)

Point = tuple[int, int, int, int]                           # extended coordinates (X, Y, Z, T)


def _recover_x(y: int, sign: int) -> Optional[int]:
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


def _add(a: Point, b: Point) -> Point:
    A = (a[1] - a[0]) * (b[1] - b[0]) % P
    B = (a[1] + a[0]) * (b[1] + b[0]) % P
    C = 2 * a[3] * b[3] * D % P
    Dd = 2 * a[2] * b[2] % P
    E, F, G, H = B - A, Dd - C, Dd + C, B + A
    return (E * F % P, G * H % P, F * G % P, E * H % P)


def _mul(s: int, pt: Point) -> Point:
    q: Point = (0, 1, 1, 0)                                 # the neutral element
    while s:
        if s & 1:
            q = _add(q, pt)
        pt = _add(pt, pt)
        s >>= 1
    return q


def _equal(a: Point, b: Point) -> bool:
    return (a[0] * b[2] - b[0] * a[2]) % P == 0 and (a[1] * b[2] - b[1] * a[2]) % P == 0


def _decompress(raw: bytes) -> Optional[Point]:
    if len(raw) != 32:
        return None
    y = int.from_bytes(raw, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % P)


_GY = 4 * pow(5, P - 2, P) % P
_GX = _recover_x(_GY, 0)
assert _GX is not None
BASE: Point = (_GX, _GY, 1, _GX * _GY % P)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """True when `signature` is `public_key`'s Ed25519 signature of `message`."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a = _decompress(public_key)
    r = _decompress(signature[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:                                              # non-canonical: refused (RFC 8032)
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % L
    return _equal(_mul(s, BASE), _add(r, _mul(h, a)))
