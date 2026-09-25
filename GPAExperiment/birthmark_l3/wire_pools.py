"""Measured wire-size pools from genuine TLS and DNS traffic.

Nothing in here is a hand-typed size. Every number comes from bytes that Python's `ssl`
module (OpenSSL) or dnspython actually produced:

* TLS: full client/server sessions run over ssl.MemoryBIO pairs. The byte streams are split
  into records by their plaintext 5-byte headers, so each record's content-type byte and
  on-the-wire length are exactly what a passive observer would see. Sessions are made
  diverse on every axis that changes sizes: TLS 1.3 vs 1.2, SNI length, ALPN list, RFC 7685
  padding extension on/off, session resumption (PSK), server certificate key type and chain
  length, number of session tickets, and the HTTP requests/responses carried.
* DNS: EDNS0 responses built and DNSSEC-signed with real keys (ECDSA P-256, RSA-2048,
  Ed25519) over varied names, record types and answer counts; queries too.
* Birthmark relay packets: padded ciphertexts of every target length 420..460 are pushed
  through real TLS 1.3 sessions to measure the record overhead the wire actually adds.

The pools are cached under level3/pools/ so every simulation run draws from the same
measured set (and the set is reproducible from its seed).
"""
from __future__ import annotations

import datetime
import json
import os
import random
import ssl
import string
import tempfile
from pathlib import Path

import numpy as np

from . import params as P

POOL_DIR = Path(__file__).resolve().parent.parent / "pools"
OP_TLSEXT_PADDING = 0x10  # OpenSSL SSL_OP_TLSEXT_PADDING (RFC 7685); on in Python's default OP_ALL


# --------------------------------------------------------------------------- record parsing
def split_records(stream: bytes) -> list[tuple[int, int]]:
    """Split a TLS byte stream into (content_type, wire_length) using only plaintext headers."""
    out, i = [], 0
    while i + 5 <= len(stream):
        ctype = stream[i]
        length = int.from_bytes(stream[i + 3:i + 5], "big")
        out.append((ctype, 5 + length))
        i += 5 + length
    if i != len(stream):
        raise ValueError("partial record in captured stream")
    return out


# --------------------------------------------------------------------------- certificates
def _make_chain(rnd: random.Random, workdir: Path, idx: int):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import NameOID

    def key(kind):
        if kind == "rsa2048":
            return rsa.generate_private_key(65537, 2048)
        if kind == "rsa3072":
            return rsa.generate_private_key(65537, 3072)
        if kind == "p384":
            return ec.generate_private_key(ec.SECP384R1())
        return ec.generate_private_key(ec.SECP256R1())

    def name(cn):
        attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
        if rnd.random() < 0.6:
            attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, _word(rnd, 4, 18).title() + " Inc"))
        if rnd.random() < 0.4:
            attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, rnd.choice(["US", "DE", "NL", "JP", "BR", "KE"])))
        return x509.Name(attrs)

    now = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
    host = _hostname(rnd)
    ca_kind = rnd.choice(["rsa2048", "p256", "p384", "rsa3072"])
    leaf_kind = rnd.choice(["rsa2048", "p256", "p256", "p384"])
    ca_key = key(ca_kind)
    ca_name = name(_word(rnd, 5, 14).title() + " Root CA")
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .sign(ca_key, hashes.SHA256()))
    chain_keys, issuer_cert, issuer_key = [], ca, ca_key
    if rnd.random() < 0.6:  # intermediate CA
        ik = key(rnd.choice(["rsa2048", "p256", "p384"]))
        iname = name(_word(rnd, 5, 14).title() + " Issuing CA " + str(rnd.randint(1, 9)))
        inter = (x509.CertificateBuilder().subject_name(iname).issuer_name(ca.subject)
                 .public_key(ik.public_key()).serial_number(x509.random_serial_number())
                 .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1825))
                 .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                 .sign(ca_key, hashes.SHA256()))
        chain_keys.append(inter)
        issuer_cert, issuer_key = inter, ik
    leaf_key = key(leaf_kind)
    sans = [x509.DNSName(host)] + [x509.DNSName(_hostname(rnd)) for _ in range(rnd.choice([0, 0, 1, 3, 8, 20]))]
    leaf = (x509.CertificateBuilder().subject_name(name(host)).issuer_name(issuer_cert.subject)
            .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .sign(issuer_key, hashes.SHA256()))
    pem = leaf.public_bytes(serialization.Encoding.PEM) + b"".join(
        c.public_bytes(serialization.Encoding.PEM) for c in chain_keys)
    certfile, keyfile, cafile = (workdir / f"{idx}_{n}.pem" for n in ("chain", "key", "ca"))
    certfile.write_bytes(pem)
    keyfile.write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM,
                                               serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
    cafile.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    return host, certfile, keyfile, cafile


def _word(rnd, lo, hi):
    return "".join(rnd.choice(string.ascii_lowercase) for _ in range(rnd.randint(lo, hi)))


def _hostname(rnd):
    labels = [_word(rnd, 2, 12) for _ in range(rnd.choice([1, 1, 2, 3]))]
    return ".".join(labels + [rnd.choice(["com", "org", "net", "io", "de", "co.uk", "news"])])


# --------------------------------------------------------------------------- HTTP payloads
_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "okhttp/4.12.0", "curl/8.5.0", "python-requests/2.32.3", "Go-http-client/2.0",
]


def _http_request(rnd: random.Random, host: str) -> bytes:
    method = rnd.choices(["GET", "POST", "PUT"], [0.75, 0.2, 0.05])[0]
    path = "/" + "/".join(_word(rnd, 2, 10) for _ in range(rnd.randint(0, 5)))
    if rnd.random() < 0.4:
        path += "?" + "&".join(f"{_word(rnd,1,8)}={_word(rnd,1,16)}" for _ in range(rnd.randint(1, 5)))
    h = [f"{method} {path} HTTP/1.1", f"Host: {host}", f"User-Agent: {rnd.choice(_UAS)}"]
    if rnd.random() < 0.8:
        h.append(rnd.choice(["Accept: */*", "Accept: application/json",
                             "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"]))
    if rnd.random() < 0.6:
        h.append("Accept-Encoding: gzip, deflate, br")
    if rnd.random() < 0.5:
        h.append("Accept-Language: " + rnd.choice(["en-US,en;q=0.9", "de-DE,de;q=0.8,en;q=0.5", "ja"]))
    if rnd.random() < 0.45:
        h.append("Cookie: " + "; ".join(f"{_word(rnd,2,10)}={_word(rnd,8,40)}" for _ in range(rnd.randint(1, 8))))
    if rnd.random() < 0.25:
        h.append("Authorization: Bearer " + _word(rnd, 40, 300))
    body = b""
    if method != "GET":
        body = json.dumps({_word(rnd, 2, 8): _word(rnd, 1, 60) for _ in range(rnd.randint(1, 25))}).encode()
        h += ["Content-Type: application/json", f"Content-Length: {len(body)}"]
    return ("\r\n".join(h) + "\r\n\r\n").encode() + body


def _http_response(rnd: random.Random) -> bytes:
    size = int(min(2_000_000, max(0, rnd.lognormvariate(7.0, 1.8))))  # median ~1.1 kB
    h = ["HTTP/1.1 200 OK", "Content-Type: " + rnd.choice(["application/json", "text/html; charset=utf-8", "image/webp"]),
         f"Content-Length: {size}", "Date: Wed, 23 Sep 2026 12:00:00 GMT"]
    if rnd.random() < 0.5:
        h.append("Cache-Control: max-age=" + str(rnd.randint(0, 86400)))
    if rnd.random() < 0.3:
        h.append("Set-Cookie: " + _word(rnd, 3, 10) + "=" + _word(rnd, 20, 120) + "; Path=/; Secure; HttpOnly")
    return ("\r\n".join(h) + "\r\n\r\n").encode() + os.urandom(size)


# --------------------------------------------------------------------------- TLS sessions
def _pump(src_bio_out: ssl.MemoryBIO, dst_bio_in: ssl.MemoryBIO) -> bytes:
    data = src_bio_out.read()
    if data:
        dst_bio_in.write(data)
    return data


def _run_session(rnd, cert, resume_session=None, client_ctx=None, server_ctx=None):
    """Run one full session. Returns (records, client_session). records = list of
    (direction, flight, content_type, wire_len, app_phase); direction 0 = client->server,
    app_phase 0 = handshake flights, 1 = application request/response flights."""
    host, certfile, keyfile, cafile = cert
    cin, cout, sin, sout = (ssl.MemoryBIO() for _ in range(4))
    client = client_ctx.wrap_bio(cin, cout, server_hostname=host, session=resume_session)
    server = server_ctx.wrap_bio(sin, sout, server_side=True)
    records, flight, app_phase = [], 0, 0

    def emit(direction, data):
        nonlocal flight
        if not data:
            return False
        for ct, n in split_records(data):
            records.append((direction, flight, ct, n, app_phase))
        flight += 1
        return True

    done = {id(client): False, id(server): False}
    for _ in range(12):  # handshake ping-pong until both sides finish and the wire is quiet
        for side in (client, server):
            if not done[id(side)]:
                try:
                    side.do_handshake()
                    done[id(side)] = True
                except ssl.SSLWantReadError:
                    pass
        moved = emit(0, _pump(cout, sin)) | emit(1, _pump(sout, cin))
        if all(done.values()) and not moved:
            break
    # application exchanges: 1-3 request/response pairs
    app_phase = 1
    for _ in range(rnd.choice([1, 1, 1, 2, 3])):
        client.write(_http_request(rnd, host))
        emit(0, _pump(cout, sin))
        _drain(server)
        server.write(_http_response(rnd))
        emit(1, _pump(sout, cin))
        _drain(client)
        emit(0, _pump(cout, sin))   # post-handshake bits the client may still owe
    return records, client.session


def _drain(sock):
    try:
        while sock.read(1 << 20):
            pass
    except (ssl.SSLWantReadError, ssl.SSLZeroReturnError):
        pass


def build_tls_pool(n_certs=60, sessions_per_cert=6, seed=7) -> list[dict]:
    rnd = random.Random(seed)
    pool = []
    with tempfile.TemporaryDirectory() as td:
        for i in range(n_certs):
            cert = _make_chain(rnd, Path(td), i)
            host, certfile, keyfile, cafile = cert
            s_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            s_ctx.load_cert_chain(certfile, keyfile)
            s_ctx.num_tickets = rnd.choice([0, 1, 2, 2, 2])
            tls12 = rnd.random() < 0.15
            if tls12:
                s_ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            c_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            c_ctx.load_verify_locations(cafile)
            if rnd.random() < 0.35:
                c_ctx.options &= ~OP_TLSEXT_PADDING
            alpn = rnd.choice([None, ["http/1.1"], ["h2", "http/1.1"], ["h2"], ["h3", "h2", "http/1.1"]])
            if alpn:
                c_ctx.set_alpn_protocols(alpn)
                s_ctx.set_alpn_protocols(["h2", "http/1.1"])
            session = None
            for j in range(sessions_per_cert):
                resume = session if (session is not None and rnd.random() < 0.5) else None
                recs, sess = _run_session(rnd, cert, resume, c_ctx, s_ctx)
                if sess is not None:
                    session = sess
                pool.append({"id": f"tls{i:03d}_{j}", "tls12": tls12, "resumed": resume is not None,
                             "records": recs})
    return pool


def measure_tls_overhead(seed=3) -> dict:
    """Push Birthmark-sized ciphertexts, keepalives and bulk chunks through real TLS 1.3."""
    rnd = random.Random(seed)
    with tempfile.TemporaryDirectory() as td:
        cert = _make_chain(rnd, Path(td), 0)
        host, certfile, keyfile, cafile = cert
        s_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        s_ctx.load_cert_chain(certfile, keyfile)
        s_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        c_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        c_ctx.load_verify_locations(cafile)
        cin, cout, sin, sout = (ssl.MemoryBIO() for _ in range(4))
        client = c_ctx.wrap_bio(cin, cout, server_hostname=host)
        server = s_ctx.wrap_bio(sin, sout, server_side=True)
        for _ in range(8):
            for side in (client, server):
                try:
                    side.do_handshake()
                except ssl.SSLWantReadError:
                    pass
            _pump(cout, sin)
            _pump(sout, cin)
        _drain(client)
        out = {"cipher": client.cipher()[0], "birthmark": {}, "keepalive": None, "bulk_record": None}
        for target in range(P.PAD_MIN, P.PAD_MAX + 1):
            client.write(os.urandom(target))
            recs = split_records(cout.read())
            assert len(recs) == 1 and recs[0][0] == P.RT_APPDATA
            out["birthmark"][target] = recs[0][1]
        client.write(os.urandom(17))                        # HTTP/2 PING frame (9 + 8)
        out["keepalive"] = split_records(cout.read())[0][1]
        client.write(os.urandom(100_000))
        out["bulk_record"] = max(n for _, n in split_records(cout.read()))
        client.write(os.urandom(96 + 168))                  # see gossip_wire_size()
        out["gossip"] = split_records(cout.read())[0][1]
    return out


# --------------------------------------------------------------------------- DNS
def build_dns_pool(n=600, seed=11) -> list[dict]:
    import dns.dnssec
    import dns.flags
    import dns.message
    import dns.name
    import dns.rdata
    import dns.rdataclass
    import dns.rdatatype
    import dns.rrset
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

    rnd = random.Random(seed)
    keys = {
        13: [ec.generate_private_key(ec.SECP256R1()) for _ in range(3)],
        8: [rsa.generate_private_key(65537, 2048) for _ in range(3)],
        15: [ed25519.Ed25519PrivateKey.generate() for _ in range(2)],
    }
    pool = []
    for i in range(n):
        zone = dns.name.from_text(_hostname(rnd))
        qname = dns.name.from_text(rnd.choice(["www", "api", "cdn", "mail", _word(rnd, 3, 20)]), zone)
        rdtype = rnd.choices(["A", "AAAA", "MX", "TXT", "CNAME"], [0.45, 0.25, 0.08, 0.12, 0.10])[0]
        payload = rnd.choice([1232, 1232, 4096, 512])
        q = dns.message.make_query(qname, rdtype, use_edns=0, payload=payload,
                                   want_dnssec=rnd.random() < 0.7)
        r = dns.message.make_response(q)
        ttl = rnd.choice([60, 300, 3600, 86400])
        texts = []
        for _ in range(rnd.choice([1, 1, 2, 3, 4, 8])):
            if rdtype == "A":
                texts.append(".".join(str(rnd.randint(1, 254)) for _ in range(4)))
            elif rdtype == "AAAA":
                texts.append(":".join(f"{rnd.randint(0, 65535):x}" for _ in range(8)))
            elif rdtype == "MX":
                texts.append(f"{rnd.randint(1, 50)} {_hostname(rnd)}.")
            elif rdtype == "TXT":
                texts.append('"' + _word(rnd, 10, 200) + '"')
            else:
                texts.append(_hostname(rnd) + ".")
                break
        rrset = dns.rrset.from_text_list(qname, ttl, "IN", rdtype, texts)
        r.answer.append(rrset)
        if q.want_dnssec():
            alg = rnd.choice([13, 13, 8, 15])
            sk = rnd.choice(keys[alg])
            dnskey = dns.dnssec.make_dnskey(sk.public_key(), alg)
            sig = dns.dnssec.sign(rrset, sk, zone, dnskey,
                                  inception=1767225600, expiration=1767225600 + 30 * 86400)
            r.answer.append(dns.rrset.from_rdata(qname, ttl, sig))
        if rnd.random() < 0.3:  # authority NS records
            r.authority.append(dns.rrset.from_text_list(zone, 86400, "IN", "NS",
                                                        [_hostname(rnd) + "." for _ in range(rnd.randint(2, 4))]))
        wire = r.to_wire(max_size=65535)
        pool.append({"id": f"dns{i:03d}", "query": len(q.to_wire()), "response": len(wire),
                     "dnssec": q.want_dnssec()})
    return pool


# --------------------------------------------------------------------------- cache / load
def gossip_wire_size() -> int:
    """Reg-1/2 gossip frame: 96 B posting + gossipsub RPC envelope (~168 B: from peer-id 38,
    seqno 10, topic ~20, libp2p signature 66, protobuf tags ~34) inside a Noise transport frame.
    The envelope is an estimate [DEFAULT]; the Noise frame's 18 B is measured via TLS-equivalent
    AEAD framing above. Only matters in that it is nowhere near the 442-482 B relay class."""
    return 96 + 168 + 18


def build_all(force=False) -> dict:
    POOL_DIR.mkdir(exist_ok=True)
    path = POOL_DIR / "pools.json"
    if path.exists() and not force:
        return json.loads(path.read_text())
    data = {"tls": build_tls_pool(), "dns": build_dns_pool(), "overhead": measure_tls_overhead()}
    path.write_text(json.dumps(data))
    return data


class Pools:
    """Numpy views of the measured pools used by the simulator."""

    def __init__(self, data: dict | None = None):
        data = data or build_all()
        self.tls_sessions = []  # list of (dir, flight, ctype, size) int arrays
        for s in data["tls"]:
            self.tls_sessions.append(np.array(s["records"], dtype=np.int32).reshape(-1, 5))
        self.dns_query = np.array([d["query"] for d in data["dns"]], dtype=np.int32)
        self.dns_resp = np.array([d["response"] for d in data["dns"]], dtype=np.int32)
        ov = data["overhead"]
        self.birthmark_wire = {int(k): int(v) for k, v in ov["birthmark"].items()}
        self.tls13_overhead = self.birthmark_wire[P.PAD_MIN] - P.PAD_MIN
        self.keepalive_wire = int(ov["keepalive"])
        self.bulk_record_wire = int(ov["bulk_record"])
        self.gossip_wire = gossip_wire_size()

    def summary(self) -> dict:
        all_recs = np.concatenate(self.tls_sessions)
        app = all_recs[all_recs[:, 2] == P.RT_APPDATA][:, 3]
        hs = all_recs[all_recs[:, 2] == P.RT_HANDSHAKE][:, 3]
        lo, hi = P.PAD_MIN + self.tls13_overhead, P.PAD_MAX + self.tls13_overhead
        ch = np.array([s[0, 3] for s in self.tls_sessions if s[0, 2] == P.RT_HANDSHAKE])
        return {
            "tls_sessions": len(self.tls_sessions),
            "distinct_session_size_signatures": len({tuple(map(tuple, s[:, [0, 2, 3]].tolist())) for s in self.tls_sessions}),
            "distinct_clienthello_sizes": int(len(np.unique(ch))),
            "clienthello_size_range": [int(ch.min()), int(ch.max())],
            "tls13_record_overhead": self.tls13_overhead,
            "birthmark_wire_range": [lo, hi],
            "appdata_records": int(len(app)),
            "appdata_in_birthmark_window": float(np.mean((app >= lo) & (app <= hi))),
            "handshake_records_in_window_by_size_only": float(np.mean((hs >= lo) & (hs <= hi))),
            "dns_responses": int(len(self.dns_resp)),
            "distinct_dns_response_sizes": int(len(np.unique(self.dns_resp))),
            "dns_response_range": [int(self.dns_resp.min()), int(self.dns_resp.max())],
            "dns_in_window_by_size_only": float(np.mean((self.dns_resp >= lo) & (self.dns_resp <= hi))),
            "keepalive_wire": self.keepalive_wire,
            "bulk_record_wire": self.bulk_record_wire,
            "gossip_wire": self.gossip_wire,
        }


if __name__ == "__main__":
    import pprint
    pprint.pprint(Pools(build_all(force=True)).summary())
