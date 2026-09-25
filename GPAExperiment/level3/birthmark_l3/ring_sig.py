"""1-out-of-n Schnorr ring signature (Abe, Ohkubo, Suzuki, ASIACRYPT 2002), unlinkable.

Built only from libsodium's Ed25519 group operations via PyNaCl: base-point and variable-base
scalar multiplication, point addition, and scalar arithmetic modulo the group order. The hash to a
scalar is SHA-512 reduced mod l, the construction libsodium itself uses for Ed25519.

C signs as one member of a ring of public keys. A verifier learns that some member of the ring
signed and nothing about which one: every ring position's (c_i, r_i) pair is uniformly distributed
whether or not it is the signer's. The scheme has no key image, so two signatures by the same C
cannot be linked to each other.

Signature layout: c_0 || r_0 || r_1 || ... || r_{n-1}, each 32 bytes, so 32 * (n + 1) bytes.
"""
from __future__ import annotations

import hashlib
import os

from nacl import bindings as S

SCALAR = 32


def _random_scalar() -> bytes:
    """Uniform scalar mod l: 64 random bytes reduced mod the group order (as libsodium does)."""
    return S.crypto_core_ed25519_scalar_reduce(os.urandom(64))


class RingKey:
    def __init__(self):
        self.sk = _random_scalar()
        self.pk = S.crypto_scalarmult_ed25519_base_noclamp(self.sk)


def _h(ring: list[bytes], msg: bytes, point: bytes) -> bytes:
    d = hashlib.sha512(b"birthmark-aos-ring" + len(ring).to_bytes(2, "big") + b"".join(ring)
                       + len(msg).to_bytes(4, "big") + msg + point).digest()
    return S.crypto_core_ed25519_scalar_reduce(d)


def _commit(r: bytes, c: bytes, pk: bytes) -> bytes:
    """R = r*B + c*P."""
    return S.crypto_core_ed25519_add(S.crypto_scalarmult_ed25519_base_noclamp(r),
                                     S.crypto_scalarmult_ed25519_noclamp(c, pk))


def sign(msg: bytes, ring: list[bytes], signer: int, key: RingKey) -> bytes:
    n = len(ring)
    if ring[signer] != key.pk:
        raise ValueError("signer's key is not at the stated ring position")
    c = [b""] * n
    r = [b""] * n
    alpha = _random_scalar()
    c[(signer + 1) % n] = _h(ring, msg, S.crypto_scalarmult_ed25519_base_noclamp(alpha))
    i = (signer + 1) % n
    while i != signer:
        r[i] = _random_scalar()
        c[(i + 1) % n] = _h(ring, msg, _commit(r[i], c[i], ring[i]))
        i = (i + 1) % n
    r[signer] = S.crypto_core_ed25519_scalar_sub(alpha, S.crypto_core_ed25519_scalar_mul(c[signer], key.sk))
    return c[0] + b"".join(r)


def verify(msg: bytes, ring: list[bytes], sig: bytes) -> bool:
    n = len(ring)
    if len(sig) != SCALAR * (n + 1):
        return False
    c0 = sig[:SCALAR]
    c = c0
    try:
        for i in range(n):
            r = sig[SCALAR * (i + 1):SCALAR * (i + 2)]
            c = _h(ring, msg, _commit(r, c, ring[i]))
    except Exception:
        return False
    return c == c0


def size(n: int) -> int:
    return SCALAR * (n + 1)
