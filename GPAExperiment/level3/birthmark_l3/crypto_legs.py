"""Byte-exact construction of every leg in the Leg Catalog, using real primitives.

Primitives (chosen to reproduce the component sizes on the Size Verification tab):
  ECIES     secp256k1 ephemeral key (33 B compressed) + HKDF-SHA256 -> AES-256-GCM key and
            nonce (nonce derived, not sent) + 16 B tag  => 49 B overhead per layer
  Symmetric AES-256-GCM under the single-use BlindShare_key, fixed nonce (safe because the
            key is used exactly once)  => 32 B PacketHash -> 48 B
  Signature Ed25519, 64 B

Every relay-hop packet is  transit_layer( pad( inner ) ), where the padding sits INSIDE the
transit encryption and is sized so the finished ciphertext equals a target drawn uniformly
from [420, 460] (Simulation Parameters!C3: pad *to* a drawn target, not *by* a drawn amount).
"""
from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import params as P

ECIES_OVERHEAD = 33 + 16
PAD_LEN_PREFIX = 2          # 2-byte length prefix so the receiver can strip padding
ROUTING_CODE_LEN = 16
KEY_REF_LEN = 8
DECISION_LEN = 4


# --------------------------------------------------------------------------- primitives
class EciesKey:
    def __init__(self):
        self.sk = ec.generate_private_key(ec.SECP256K1())
        self.pk = self.sk.public_key()


def _kdf(shared: bytes, eph: bytes) -> tuple[bytes, bytes]:
    okm = HKDF(algorithm=hashes.SHA256(), length=44, salt=None, info=b"birthmark-ecies" + eph).derive(shared)
    return okm[:32], okm[32:]


def ecies_encrypt(pk: ec.EllipticCurvePublicKey, plaintext: bytes) -> bytes:
    eph = ec.generate_private_key(ec.SECP256K1())
    eph_pub = eph.public_key().public_bytes(serialization.Encoding.X962,
                                            serialization.PublicFormat.CompressedPoint)
    key, nonce = _kdf(eph.exchange(ec.ECDH(), pk), eph_pub)
    return eph_pub + AESGCM(key).encrypt(nonce, plaintext, None)


def ecies_decrypt(k: EciesKey, blob: bytes) -> bytes:
    eph_pub = blob[:33]
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), eph_pub)
    key, nonce = _kdf(k.sk.exchange(ec.ECDH(), peer), eph_pub)
    return AESGCM(key).decrypt(nonce, blob[33:], None)


def blindshare_encrypt(key: bytes, pt: bytes) -> bytes:
    return AESGCM(key).encrypt(b"\x00" * 12, pt, None)


def blindshare_decrypt(key: bytes, ct: bytes) -> bytes:
    return AESGCM(key).decrypt(b"\x00" * 12, ct, None)


def pad_to(inner: bytes, plaintext_target: int) -> bytes:
    need = plaintext_target - PAD_LEN_PREFIX - len(inner)
    if need < 0:
        raise ValueError(f"raw payload {len(inner)} B exceeds padding target {plaintext_target} B")
    return struct.pack(">H", len(inner)) + inner + b"\x00" * need


def unpad(padded: bytes) -> bytes:
    (n,) = struct.unpack(">H", padded[:2])
    return padded[2:2 + n]


def transit_wrap(pk, inner: bytes, target: int | None, rng=None) -> bytes:
    """One hop's transit layer. target=None -> unpadded (positive-control mode)."""
    if target is None:
        return ecies_encrypt(pk, inner)
    return ecies_encrypt(pk, pad_to(inner, target - ECIES_OVERHEAD))


def transit_unwrap(k: EciesKey, blob: bytes, padded: bool = True) -> bytes:
    pt = ecies_decrypt(k, blob)
    return unpad(pt) if padded else pt


def draw_target(rng) -> int:
    return int(rng.integers(P.PAD_MIN, P.PAD_MAX + 1))


# --------------------------------------------------------------------------- key material
@dataclass
class ServerKeys:
    """One pool node. Every node can play every role (Legend: letters are role slots)."""
    transit: EciesKey          # hop-specific transit layer terminates here
    terminus: EciesKey         # relay-terminus key (C-device_pk / F-device_pk / I-device_pk)
    sign: Ed25519PrivateKey    # submission-server signing key (C-signature, g_sign, f/i_device_sk)

    @classmethod
    def new(cls):
        return cls(EciesKey(), EciesKey(), Ed25519PrivateKey.generate())


@dataclass
class ValidatorKeys:
    transit: EciesKey
    token: EciesKey            # V-token_pk / V-token_sk
    sign: Ed25519PrivateKey

    @classmethod
    def new(cls):
        return cls(EciesKey(), EciesKey(), Ed25519PrivateKey.generate())


# --------------------------------------------------------------------------- device side
@dataclass
class Submission:
    content_hash: bytes
    nonce: bytes
    packet_hash: bytes
    enc_token: bytes
    key_ref: bytes


def new_submission(device_id: bytes, validator: ValidatorKeys) -> Submission:
    content_hash = hashlib.sha256(os.urandom(64)).digest()
    n = os.urandom(16)
    return Submission(
        content_hash=content_hash,
        nonce=n,
        packet_hash=hashlib.sha256(content_hash + n).digest(),
        enc_token=ecies_encrypt(validator.token.pk, device_id),     # 33 + 32 + 16 = 81
        key_ref=os.urandom(KEY_REF_LEN),
    )


def routing_code(node_index: int) -> bytes:
    return hashlib.sha256(b"route" + struct.pack(">I", node_index)).digest()[:ROUTING_CODE_LEN]


def cred_payload(sub: Submission, C: ServerKeys) -> bytes:
    """Enc(enc_token, PacketHash; C-device_pk)  (key reference travels with the token)."""
    return ecies_encrypt(C.terminus.pk, sub.enc_token + sub.key_ref + sub.packet_hash)


def content_payload(sub: Submission, F: ServerKeys) -> bytes:
    """Enc(ContentHash, n; F-device_pk)."""
    return ecies_encrypt(F.terminus.pk, sub.content_hash + sub.nonce)


def first_hop(payload: bytes, dest_index: int, first: ServerKeys, target) -> bytes:
    """Cred-1 / ContA-1 / ContB-1: Enc(routing_code || payload, Device-<first> transit)."""
    return transit_wrap(first.transit.pk, routing_code(dest_index) + payload, target)


def addressed_hop_forward(blob: bytes, me: ServerKeys, nxt: ServerKeys, target, padded=True) -> bytes:
    """Cred-2 / ContA-2 / ContB-2: the Addressed hop reads routing code, re-encrypts BOTH for the
    Random hop, then discards the routing code (paper §3.2 discard discipline)."""
    inner = transit_unwrap(me.transit, blob, padded)
    out = transit_wrap(nxt.transit.pk, inner, target)
    del inner
    return out


def random_hop_forward(blob: bytes, me: ServerKeys, lookup_dest, target, padded=True):
    """Cred-3 / ContA-3 / ContB-3: the Random hop reads (consumes) the routing code and forwards
    only the payload. Returns (destination_index, packet)."""
    inner = transit_unwrap(me.transit, blob, padded)
    code, payload = inner[:ROUTING_CODE_LEN], inner[ROUTING_CODE_LEN:]
    dest_index, dest = lookup_dest(code)
    return dest_index, transit_wrap(dest.transit.pk, payload, target)


# --------------------------------------------------------------------------- credential side
def cv1(enc_token: bytes, packet_hash: bytes, V: ValidatorKeys, target):
    """C -> validator: enc_token, wrapped = Enc(PacketHash, BlindShare_key). Returns (pkt, key)."""
    blindshare_key = AESGCM.generate_key(bit_length=256)
    wrapped = blindshare_encrypt(blindshare_key, packet_hash)            # 48 B
    return transit_wrap(V.transit.pk, enc_token + wrapped, target), blindshare_key


def cv2(blob: bytes, V: ValidatorKeys, C: ServerKeys, target, padded=True):
    """Validator -> C: decision, sign(wrapped, V-token_sk). The validator opens its transit layer
    and the token; it cannot open `wrapped` (it never holds BlindShare_key)."""
    inner = transit_unwrap(V.transit, blob, padded)
    enc_token, wrapped = inner[:81], inner[81:]
    ecies_decrypt(V.token, enc_token)                                   # membership check
    sig = V.sign.sign(wrapped)
    return transit_wrap(C.transit.pk, b"OK\x00\x00" + wrapped + sig, target)


def gk_fanout(packet_hash, wrapped, v_sig, blindshare_key, C: ServerKeys, gks, targets):
    """C -> each gatekeeper: PacketHash, Enc_PacketHash, validator sig, BlindShare_key,
    C-signature, separately encrypted per gatekeeper."""
    c_sig = C.sign.sign(packet_hash)
    body = packet_hash + wrapped + v_sig + blindshare_key + c_sig        # 240 B
    return [transit_wrap(g.transit.pk, body, t) for g, t in zip(gks, targets)], c_sig


def reg_posting(content_hash: bytes, server: ServerKeys) -> bytes:
    """Reg-1 / Reg-2: ContentHash, sign(ContentHash, f/i_device_sk). Unpadded, 96 B."""
    return content_hash + server.sign.sign(content_hash)


# --------------------------------------------------------------------------- size check
WORKBOOK_RAW_SIZES = {  # Size Verification!D column (corrected workbook: nested payload-key layer included)
    "Cred-1": 235, "Cred-2": 235, "Cred-3": 219,
    "ContA-1": 162, "ContA-2": 162, "ContA-3": 146,
    "GK": 289, "CV-1": 178, "CV-2": 165, "Reg": 96,
}


def measure_raw_sizes() -> dict[str, int]:
    """Build one of every leg with real crypto, unpadded, and return its byte length."""
    C, F, A, B, D, E = (ServerKeys.new() for _ in range(6))
    V = ValidatorKeys.new()
    sub = new_submission(os.urandom(32), V)
    cp = cred_payload(sub, C)
    cred1 = first_hop(cp, 0, A, None)
    cred2 = addressed_hop_forward(cred1, A, B, None, padded=False)
    _, cred3 = random_hop_forward(cred2, B, lambda code: (0, C), None, padded=False)
    kp = content_payload(sub, F)
    cont1 = first_hop(kp, 1, D, None)
    cont2 = addressed_hop_forward(cont1, D, E, None, padded=False)
    _, cont3 = random_hop_forward(cont2, E, lambda code: (1, F), None, padded=False)
    cv1_pkt, bsk = cv1(sub.enc_token, sub.packet_hash, V, None)
    cv2_pkt = cv2(cv1_pkt, V, C, None, padded=False)
    wrapped = blindshare_encrypt(bsk, sub.packet_hash)
    gk_pkts, _ = gk_fanout(sub.packet_hash, wrapped, V.sign.sign(wrapped), bsk, C, [A], [None])
    return {
        "Cred-1": len(cred1), "Cred-2": len(cred2), "Cred-3": len(cred3),
        "ContA-1": len(cont1), "ContA-2": len(cont2), "ContA-3": len(cont3),
        "GK": len(gk_pkts[0]), "CV-1": len(cv1_pkt), "CV-2": len(cv2_pkt),
        "Reg": len(reg_posting(sub.content_hash, F)),
    }


def size_verification_report() -> list[tuple[str, int, int, str]]:
    measured = measure_raw_sizes()
    rows = []
    for leg, wb in WORKBOOK_RAW_SIZES.items():
        m = measured[leg]
        if m == wb:
            note = "matches"
        elif m - wb == ECIES_OVERHEAD:
            note = "+49: nested payload-key ECIES layer (C/F/I-device_pk) not counted in workbook"
        else:
            note = f"differs by {m - wb:+d}"
        rows.append((leg, wb, m, note))
    return rows


# Raw sizes the fast simulator uses (as measured, not as tabulated), keyed by leg family.
def raw_size_table() -> dict[str, int]:
    return measure_raw_sizes()
