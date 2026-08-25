"""Small verification-only Ed25519 reference for O-14 falsification.

This module is deliberately isolated evidence code.  It is not constant-time,
must never be imported by product code, and is not a signing implementation for
Styx.  Its formulas follow RFC 8032 section 5.1 and expose both cofactored and
cofactorless verification so the task can make their accepted-language
difference executable.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha512


P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
BASE_X = 15112221349535400772501151409588531511454012693041857206046113283949847762202
BASE_Y = 46316835694926478169428394003475163141307993866256225615783033603165251855960


class PointDecodeError(ValueError):
    pass


@dataclass(frozen=True)
class Point:
    x: int
    y: int
    z: int = 1
    t: int | None = None

    def __post_init__(self) -> None:
        if self.t is None:
            object.__setattr__(self, "t", self.x * self.y % P)


IDENTITY = Point(0, 1)
BASE = Point(BASE_X, BASE_Y)


def _mod(value: int) -> int:
    return value % P


def add(left: Point, right: Point) -> Point:
    a = _mod((left.y - left.x) * (right.y - right.x))
    b = _mod((left.y + left.x) * (right.y + right.x))
    c = _mod(2 * D * int(left.t) * int(right.t))
    d = _mod(2 * left.z * right.z)
    e = _mod(b - a)
    f = _mod(d - c)
    g = _mod(d + c)
    h = _mod(b + a)
    return Point(_mod(e * f), _mod(g * h), _mod(f * g), _mod(e * h))


def double(point: Point) -> Point:
    a = _mod(point.x * point.x)
    b = _mod(point.y * point.y)
    c = _mod(2 * point.z * point.z)
    d = _mod(-a)
    e = _mod((point.x + point.y) ** 2 - a - b)
    g = _mod(d + b)
    f = _mod(g - c)
    h = _mod(d - b)
    return Point(_mod(e * f), _mod(g * h), _mod(f * g), _mod(e * h))


def scalar_mult(scalar: int, point: Point) -> Point:
    if scalar < 0:
        raise ValueError("negative scalar")
    result = IDENTITY
    addend = point
    value = scalar
    while value:
        if value & 1:
            result = add(result, addend)
        addend = double(addend)
        value >>= 1
    return result


def equal(left: Point, right: Point) -> bool:
    return (
        _mod(left.x * right.z - right.x * left.z) == 0
        and _mod(left.y * right.z - right.y * left.z) == 0
    )


def _sqrt_ratio(u: int, v: int) -> int | None:
    value = _mod(u * pow(v, P - 2, P))
    root = pow(value, (P + 3) // 8, P)
    if _mod(root * root - value) != 0:
        root = _mod(root * SQRT_M1)
    if _mod(root * root - value) != 0:
        return None
    return root


def decode(encoded: bytes, *, zip215: bool = False) -> Point:
    if len(encoded) != 32:
        raise PointDecodeError("point must be exactly 32 octets")
    raw = int.from_bytes(encoded, "little")
    sign = raw >> 255
    y_integer = raw & ((1 << 255) - 1)
    if not zip215 and y_integer >= P:
        raise PointDecodeError("non-canonical y")
    y = y_integer % P
    y2 = y * y % P
    x = _sqrt_ratio(y2 - 1, D * y2 + 1)
    if x is None:
        raise PointDecodeError("off-curve point")
    if x == 0 and sign and not zip215:
        raise PointDecodeError("invalid sign for x=0")
    if (x & 1) != sign:
        x = (-x) % P
    return Point(x, y)


def encode(point: Point) -> bytes:
    z_inv = pow(point.z, P - 2, P)
    x = point.x * z_inv % P
    y = point.y * z_inv % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def is_small_order(point: Point) -> bool:
    return equal(scalar_mult(8, point), IDENTITY)


def is_torsion_free(point: Point) -> bool:
    return equal(scalar_mult(L, point), IDENTITY)


def challenge(r_bytes: bytes, a_bytes: bytes, message: bytes) -> int:
    return int.from_bytes(sha512(r_bytes + a_bytes + message).digest(), "little") % L


def verify(
    signature: bytes,
    message: bytes,
    public_key: bytes,
    *,
    zip215: bool,
    cofactored: bool,
) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        a_point = decode(public_key, zip215=zip215)
        r_bytes = signature[:32]
        r_point = decode(r_bytes, zip215=zip215)
    except PointDecodeError:
        return False
    scalar = int.from_bytes(signature[32:], "little")
    if scalar >= L:
        return False
    k = challenge(r_bytes, public_key, message)
    left = scalar_mult(scalar, BASE)
    right = add(r_point, scalar_mult(k, a_point))
    if cofactored:
        left = scalar_mult(8, left)
        right = scalar_mult(8, right)
    return equal(left, right)


def selected_guard(public_key: bytes, signature: bytes) -> tuple[Point, Point, int]:
    if len(public_key) != 32:
        raise PointDecodeError("PUBLIC_KEY_LENGTH")
    if len(signature) != 64:
        raise PointDecodeError("SIGNATURE_LENGTH")
    a_point = decode(public_key, zip215=False)
    r_point = decode(signature[:32], zip215=False)
    scalar = int.from_bytes(signature[32:], "little")
    if scalar >= L:
        raise PointDecodeError("NON_CANONICAL_SCALAR")
    if is_small_order(a_point) or not is_torsion_free(a_point):
        raise PointDecodeError("PUBLIC_KEY_NOT_PRIME_ORDER")
    if is_small_order(r_point) or not is_torsion_free(r_point):
        raise PointDecodeError("R_NOT_PRIME_ORDER")
    return a_point, r_point, scalar


def selected_verify(signature: bytes, message: bytes, public_key: bytes) -> bool:
    try:
        selected_guard(public_key, signature)
    except PointDecodeError:
        return False
    return verify(signature, message, public_key, zip215=False, cofactored=True)


def verify_with_scalar_reduction(
    signature: bytes, message: bytes, public_key: bytes
) -> bool:
    """Test-only mutant: reduce S modulo L before the pinned equation.

    This models a verifier that omits canonical-scalar enforcement while retaining
    canonical point decoding and the RFC 8032 cofactored equation.  It is evidence
    code only and must never be used by product code.
    """

    if len(signature) != 64:
        return False
    scalar = int.from_bytes(signature[32:], "little") % L
    reduced = signature[:32] + scalar.to_bytes(32, "little")
    return verify(reduced, message, public_key, zip215=False, cofactored=True)


def sign_from_seed(seed: bytes, message: bytes) -> tuple[bytes, bytes]:
    if len(seed) != 32:
        raise ValueError("seed must be 32 octets")
    expanded = sha512(seed).digest()
    clamped = bytearray(expanded[:32])
    clamped[0] &= 248
    clamped[31] &= 63
    clamped[31] |= 64
    secret = int.from_bytes(clamped, "little")
    public_key = encode(scalar_mult(secret, BASE))
    nonce = int.from_bytes(sha512(expanded[32:] + message).digest(), "little") % L
    r_bytes = encode(scalar_mult(nonce, BASE))
    scalar = (nonce + challenge(r_bytes, public_key, message) * secret) % L
    return public_key, r_bytes + scalar.to_bytes(32, "little")


def mixed_order_forgery(seed: bytes, message: bytes) -> tuple[bytes, bytes]:
    """Return a cofactored-only signature for A+[order-2 point]."""

    expanded = sha512(seed).digest()
    clamped = bytearray(expanded[:32])
    clamped[0] &= 248
    clamped[31] &= 63
    clamped[31] |= 64
    secret = int.from_bytes(clamped, "little")
    prime = scalar_mult(secret, BASE)
    order_two = Point(0, P - 1)
    mixed = add(prime, order_two)
    public_key = encode(mixed)
    counter = 0
    while True:
        nonce = int.from_bytes(
            sha512(expanded[32:] + message + counter.to_bytes(4, "big")).digest(),
            "little",
        ) % L
        r_bytes = encode(scalar_mult(nonce, BASE))
        k = challenge(r_bytes, public_key, message)
        if k & 1:
            scalar = (nonce + k * secret) % L
            return public_key, r_bytes + scalar.to_bytes(32, "little")
        counter += 1


def mixed_order_cofactorless_valid(seed: bytes, message: bytes) -> tuple[bytes, bytes]:
    """Return a cofactorless-valid signature with mixed-order A (and maybe R)."""

    expanded = sha512(seed).digest()
    clamped = bytearray(expanded[:32])
    clamped[0] &= 248
    clamped[31] &= 63
    clamped[31] |= 64
    secret = int.from_bytes(clamped, "little")
    order_two = Point(0, P - 1)
    public_key = encode(add(scalar_mult(secret, BASE), order_two))
    counter = 0
    while True:
        nonce = int.from_bytes(
            sha512(expanded[32:] + b"cofactorless" + message + counter.to_bytes(4, "big")).digest(),
            "little",
        ) % L
        for torsion_bit in (0, 1):
            r_point = scalar_mult(nonce, BASE)
            if torsion_bit:
                r_point = add(r_point, order_two)
            r_bytes = encode(r_point)
            k = challenge(r_bytes, public_key, message)
            if torsion_bit == (k & 1):
                scalar = (nonce + k * secret) % L
                signature = r_bytes + scalar.to_bytes(32, "little")
                if verify(
                    signature,
                    message,
                    public_key,
                    zip215=False,
                    cofactored=False,
                ):
                    return public_key, signature
        counter += 1


def small_order_r_forgery(seed: bytes, message: bytes) -> tuple[bytes, bytes]:
    """Return a cofactored-only signature whose R is the order-2 point."""

    expanded = sha512(seed).digest()
    clamped = bytearray(expanded[:32])
    clamped[0] &= 248
    clamped[31] &= 63
    clamped[31] |= 64
    secret = int.from_bytes(clamped, "little")
    public_key = encode(scalar_mult(secret, BASE))
    r_bytes = encode(Point(0, P - 1))
    scalar = challenge(r_bytes, public_key, message) * secret % L
    return public_key, r_bytes + scalar.to_bytes(32, "little")


def zip215_noncanonical_key_forgery(message: bytes) -> tuple[bytes, bytes]:
    """Return a ZIP-215-only forgery using a non-canonical identity key."""

    public_key = (P + 1).to_bytes(32, "little")
    scalar = 7
    r_bytes = encode(scalar_mult(scalar, BASE))
    return public_key, r_bytes + scalar.to_bytes(32, "little")
