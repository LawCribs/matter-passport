#!/usr/bin/env python3
"""Independent Matter Passport conformance verifier - zero dependencies.

Written from the published spec documents (PROTOCOL.md, PACKAGE_FORMAT.md,
CANONICALIZATION.md, and CONFORMANCE.md). Shares no code with the
LawCribs application; every formula is reimplemented from the spec.

Subcommands:
  package <file.lcp> [--expected <dir>]   verify a .lcp package
  receipt <file.json>                      verify a transfer receipt signature
  vectors <dir>                            run the fixtures/vectors known-answer tests

Requires Python 3.9+. Stdlib only.
"""
import base64
import hashlib
import json
import math
import struct
import sys
import zipfile
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

PASS, FAIL, WARN, INFO = "pass", "fail", "warn", "info"


def out(status, label, detail):
    tag = {"pass": "PASS", "fail": "FAIL", "warn": "WARN", "info": "INFO"}[status]
    print(f"{tag}  {label}: {detail}")


def b64url_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64url_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def sha256b64(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return b64url_encode(hashlib.sha256(data).digest())


# --------------------------------------------------------------------------
# JSON parsing - JS JSON.parse semantics, not Python's lenient defaults
# --------------------------------------------------------------------------

_JS_MAX_SAFE_INT = 2 ** 53  # every integer with |v| <= 2^53 is an exact double


def _js_parse_int(s):
    """JSON.parse reads every number as an IEEE-754 double. Python keeps
    arbitrary-precision ints, so emulate the double rounding for values
    beyond the safe range - otherwise canonical bytes diverge from what
    the signer's JSON.stringify produced."""
    v = int(s)
    if -_JS_MAX_SAFE_INT <= v <= _JS_MAX_SAFE_INT:
        return v
    try:
        return float(s)
    except OverflowError:
        return math.copysign(float("inf"), v)


def _js_parse_float(s):
    # float() is correctly rounded, same as JS number parsing.
    return float(s)


def _js_parse_constant(s):
    # JS JSON.parse rejects NaN/Infinity/-Infinity literals outright.
    raise ValueError(f"invalid JSON constant: {s}")


def js_loads(s):
    """json.loads with JS semantics: strict constants, double-precision
    numbers. Use for every document whose bytes feed digests or checks."""
    return json.loads(s, parse_int=_js_parse_int, parse_float=_js_parse_float,
                      parse_constant=_js_parse_constant)


# --------------------------------------------------------------------------
# JSON serialization - must match JavaScript JSON.stringify byte-for-byte
# --------------------------------------------------------------------------

def _js_primitive(v):
    """JSON.stringify-compatible primitive serialization."""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return js_float_str(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    raise TypeError(f"not JSON-serializable: {type(v)}")


def js_float_str(f):
    """ECMAScript Number::toString as used by JSON.stringify:
    decimal notation for 1e-6 <= |n| < 1e21, exponential otherwise,
    shortest round-trip digits, no exponent padding."""
    if f != f or f in (float("inf"), float("-inf")):
        return "null"  # JSON.stringify emits null for non-finite
    if f == 0:
        return "0"  # covers -0.0 -> "0"
    sign = "-" if f < 0 else ""
    s = repr(abs(f))
    if "e" in s or "E" in s:
        mant, ex = s.lower().split("e")
        ex = int(ex)
    else:
        mant, ex = s, 0
    if "." in mant:
        ip, fp = mant.split(".")
        digits = ip + fp
        ex -= len(fp)
    else:
        digits = mant
    digits = digits.lstrip("0")
    while digits.endswith("0") and len(digits) > 1:
        digits = digits[:-1]
        ex += 1
    # value = int(digits) * 10^ex ; leading digit's power:
    n = ex + len(digits) - 1
    if n < -6 or n >= 21:
        m = digits[0] if len(digits) == 1 else digits[0] + "." + digits[1:]
        return f"{sign}{m}e{'+' if n >= 0 else '-'}{abs(n)}"
    point = ex + len(digits)
    if point <= 0:
        return sign + "0." + "0" * (-point) + digits
    if point >= len(digits):
        return sign + digits + "0" * (point - len(digits))
    return sign + digits[:point] + "." + digits[point:]


def js_dumps(v):
    """JSON.stringify equivalent: no spaces, UTF-8 literal output,
    insertion-order keys preserved."""
    if isinstance(v, dict):
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + js_dumps(x) for k, x in v.items()) + "}"
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(js_dumps(x) for x in v) + "]"
    return _js_primitive(v)


def canonicalize(v):
    """JCS-lite: object keys sorted by UTF-16 code unit order (JS sort
    semantics), then JSON.stringify. Python sorts by code point, which
    differs for astral characters - sort by UTF-16BE bytes instead."""
    def sortval(x):
        if isinstance(x, dict):
            return {k: sortval(x[k]) for k in sorted(x.keys(), key=lambda k: k.encode("utf-16-be"))}
        if isinstance(x, (list, tuple)):
            return [sortval(i) for i in x]
        return x
    return js_dumps(sortval(v))


# --------------------------------------------------------------------------
# Merkle (lc-pproof-v1)
# --------------------------------------------------------------------------

TAG = "lc-pproof-v1"


def leaf_hash(leaf):
    return sha256b64(f"{TAG}|leaf|{leaf}")


def node_hash(left, right):
    return sha256b64(f"{TAG}|node|{left}|{right}")


def merkle_root(leaves):
    level = [leaf_hash(l) for l in sorted(leaves)]
    while len(level) > 1:
        level = [node_hash(level[i], level[i + 1] if i + 1 < len(level) else level[i])
                 for i in range(0, len(level), 2)]
    return level[0] if level else ""


def merkle_proof(leaves, target):
    """Return (leaf_index_in_sorted, siblings) for target, or None."""
    sorted_leaves = sorted(leaves)
    if target not in sorted_leaves:
        return None
    idx = sorted_leaves.index(target)
    level = [leaf_hash(l) for l in sorted_leaves]
    levels = [level]
    while len(level) > 1:
        level = [node_hash(level[i], level[i + 1] if i + 1 < len(level) else level[i])
                 for i in range(0, len(level), 2)]
        levels.append(level)
    siblings = []
    i = idx
    for row in levels[:-1]:
        sib = i + 1 if i % 2 == 0 else i - 1
        sib_digest = row[sib] if sib < len(row) else row[i]
        siblings.append({"position": "right" if i % 2 == 0 else "left", "digest": sib_digest})
        i //= 2
    return {"leafIndex": idx, "siblings": siblings, "root": levels[-1][0] if levels else ""}


def verify_merkle_proof(leaf, proof):
    cur = leaf_hash(leaf)
    for s in proof["siblings"]:
        cur = node_hash(s["digest"], cur) if s["position"] == "left" else node_hash(cur, s["digest"])
    return cur == proof["root"]


# --------------------------------------------------------------------------
# ECDSA P-256 (ES256) - raw IEEE-P1363 signatures, no DER
# --------------------------------------------------------------------------

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _inv(x, m):
    return pow(x % m, -1, m)


def _ec_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * _inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * _inv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return x3, (lam * (x1 - x3) - y1) % P


def _ec_mul(k, point):
    # Fixed 256-bit double-and-add. ECDSA *verification* scalars are
    # derived entirely from public values (z = hash, r, s), so timing
    # here cannot leak a secret - but a fixed iteration count removes
    # scalar-length leakage for free and keeps the loop boring.
    result = None
    for i in range(255, -1, -1):
        result = _ec_add(result, result)
        if (k >> i) & 1:
            result = _ec_add(result, point)
    return result


def ec_verify(jwk, signature_value_b64url, message_bytes):
    """Verify an ES256 signature (raw r||s, 64 bytes) against a P-256
    public JWK over SHA-256(message_bytes). Returns bool."""
    try:
        if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
            return False
        sig = b64url_decode(signature_value_b64url)
        if len(sig) != 64:
            return False
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        if not (1 <= r < N and 1 <= s < N):
            return False
        q = (int.from_bytes(b64url_decode(jwk["x"]), "big"),
             int.from_bytes(b64url_decode(jwk["y"]), "big"))
        # On-curve check
        if (q[1] * q[1] - (q[0] * q[0] * q[0] + A * q[0] + B)) % P != 0:
            return False
        z = int.from_bytes(hashlib.sha256(message_bytes).digest(), "big")
        w = _inv(s, N)
        u1, u2 = z * w % N, r * w % N
        point = _ec_add(_ec_mul(u1, (GX, GY)), _ec_mul(u2, q))
        return point is not None and point[0] % N == r
    except Exception:
        return False


# --------------------------------------------------------------------------
# AES-256 + GCM (for the transfer-envelope vector)
# --------------------------------------------------------------------------

_SBOX = []


def _init_aes():
    global _SBOX
    p = q = 1
    sbox = [0] * 256
    # generate S-box via GF arithmetic
    def gf_mul(a, b):
        r = 0
        while b:
            if b & 1:
                r ^= a
            a = ((a << 1) ^ (0x11B if a & 0x80 else 0)) & 0xFF
            b >>= 1
        return r

    def gf_pow(a, e):
        r = 1
        while e:
            if e & 1:
                r = gf_mul(r, a)
            a = gf_mul(a, a)
            e >>= 1
        return r

    for i in range(256):
        inv = 0 if i == 0 else gf_pow(i, 254)
        s = inv
        for _ in range(4):
            inv = ((inv << 1) | (inv >> 7)) & 0xFF
            s ^= inv
        s ^= 0x63
        sbox[i] = s
    _SBOX = sbox


_init_aes()
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _key_expansion(key):
    """AES-256 key expansion -> 15 round keys of 16 bytes."""
    assert len(key) == 32
    w = [list(key[i:i + 4]) for i in range(0, 32, 4)]
    for i in range(8, 60):
        temp = list(w[i - 1])
        if i % 8 == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= _RCON[i // 8 - 1]
        elif i % 8 == 4:
            temp = [_SBOX[b] for b in temp]
        w.append([a ^ b for a, b in zip(w[i - 8], temp)])
    return _round_keys(w)


def _round_keys(w):
    keys = []
    for rk in range(15):
        block = bytearray(16)
        for c in range(4):
            for r in range(4):
                block[4 * c + r] = w[4 * rk + c][r]
        keys.append(bytes(block))
    return keys


def _xtime(a):
    return ((a << 1) ^ (0x1B if a & 0x80 else 0)) & 0xFF


def _aes_encrypt_block(block, round_keys):
    s = [list(block[4 * c:4 * c + 4]) for c in range(4)]  # column-major

    def ark(rk):
        for c in range(4):
            for r in range(4):
                s[c][r] ^= rk[4 * c + r]

    ark(round_keys[0])
    for rnd in range(1, 15):
        for c in range(4):
            for r in range(4):
                s[c][r] = _SBOX[s[c][r]]
        # ShiftRows: row r rotates left by r across columns
        for r in range(4):
            row = [s[c][r] for c in range(4)]
            row = row[r:] + row[:r]
            for c in range(4):
                s[c][r] = row[c]
        if rnd < 14:
            for c in range(4):
                a = s[c]
                s[c] = [
                    _xtime(a[0]) ^ (_xtime(a[1]) ^ a[1]) ^ a[2] ^ a[3],
                    a[0] ^ _xtime(a[1]) ^ (_xtime(a[2]) ^ a[2]) ^ a[3],
                    a[0] ^ a[1] ^ _xtime(a[2]) ^ (_xtime(a[3]) ^ a[3]),
                    (_xtime(a[0]) ^ a[0]) ^ a[1] ^ a[2] ^ _xtime(a[3]),
                ]
        ark(round_keys[rnd])
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[4 * c + r] = s[c][r]
    return bytes(out)


def _gf128_mul(x, y):
    """GF(2^128) multiply, MSB-first, modulus x^128+x^7+x^2+x+1."""
    z = 0
    v = x
    for i in range(128):
        if (y >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ 0xE1000000000000000000000000000000
        else:
            v >>= 1
    return z


def _ghash(h, data):
    y = 0
    for i in range(0, len(data), 16):
        block = data[i:i + 16].ljust(16, b"\x00")
        y = _gf128_mul(y ^ int.from_bytes(block, "big"), h)
    return y


def aes_gcm_decrypt(key, iv, data):
    """AES-256-GCM decrypt. data = ciphertext || 16-byte tag. AAD empty.
    Returns plaintext or raises ValueError on tag mismatch."""
    if len(iv) != 12:
        raise ValueError("GCM vector requires 96-bit IV")
    ct, tag = data[:-16], data[-16:]
    rk = _key_expansion(key)
    h = int.from_bytes(_aes_encrypt_block(b"\x00" * 16, rk), "big")
    j0 = iv + b"\x00" * 3 + b"\x01"  # 96-bit IV || 0^31 || 1 = 16 bytes
    # GHASH over AAD(empty) || pad || CT || pad || lens
    lens = struct.pack(">QQ", 0, len(ct) * 8)
    s = _ghash(h, ct + b"\x00" * ((-len(ct)) % 16) + lens)
    e_j0 = int.from_bytes(_aes_encrypt_block(j0, rk), "big")
    expected_tag = ((s ^ e_j0) & ((1 << 128) - 1)).to_bytes(16, "big")
    if expected_tag != tag:
        raise ValueError("GCM tag mismatch")
    # CTR mode starting at inc32(J0)
    ctr = bytearray(j0)
    plain = bytearray()
    for i in range(0, len(ct), 16):
        ctr[15] = (ctr[15] + 1) & 0xFF
        carry = 1 if ctr[15] == 0 else 0
        j = 14
        while carry and j >= 12:
            ctr[j] = (ctr[j] + 1) & 0xFF
            carry = 1 if ctr[j] == 0 else 0
            j -= 1
        ks = _aes_encrypt_block(bytes(ctr), rk)
        block = ct[i:i + 16]
        plain += bytes(a ^ b for a, b in zip(block, ks))
    return bytes(plain)


# --------------------------------------------------------------------------
# Package verification - mirrors src/lib/passport/verify.ts
# --------------------------------------------------------------------------

MAX_PACKAGE_BYTES = 256 * 1024 * 1024
MAX_FILE_COUNT = 2000
MAX_FILE_BYTES = 100 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_PATH_DEPTH = 6


def safe_path(p):
    # Entries are kept in memory and matched literally against manifest
    # contentLocations - nothing is ever extracted to disk, so traversal
    # is impossible by construction. These checks mirror verify.ts and
    # exist to reject non-conformant packages loudly, not to sanitize.
    # Note: JSZip mangles backslashes before the app verifier sees them,
    # while zipfile preserves raw names - exotic separators can therefore
    # produce WARN (digest skipped) rather than FAIL on both sides.
    return (".." not in p and not p.startswith("/") and not p[1:3] == ":\\"
            and not (len(p) > 1 and p[1] == ":") and len(p.split("/")) <= MAX_PATH_DEPTH)


def read_package(path):
    files = {}
    total = 0
    with zipfile.ZipFile(path) as z:
        infos = z.infolist()
        names = [i.filename for i in infos if not i.is_dir()]
        if len(names) > MAX_FILE_COUNT:
            raise ValueError("too many files in package")
        if len(set(names)) != len(names):
            raise ValueError("duplicate package entry")
        for info in infos:
            if info.is_dir():
                continue
            p = info.filename
            if not safe_path(p):
                raise ValueError(f"unsafe path: {p}")
            if info.file_size > MAX_FILE_BYTES:
                raise ValueError(f"file too large: {p}")
            total += info.file_size
            if total > MAX_TOTAL_BYTES:
                raise ValueError("package decompressed size limit exceeded")
        for name in names:
            files[name] = z.read(name)
    return files


def verify_package(path):
    checks = []

    def push(cid, label, status, detail):
        checks.append({"id": cid, "label": label, "status": status, "detail": detail})
        out(status, label, detail)

    try:
        if Path(path).stat().st_size > MAX_PACKAGE_BYTES:
            raise ValueError("package exceeds maximum size")
        files = read_package(path)
        push("parse", "Package parsed safely", PASS, f"{len(files)} entries within limits")
    except Exception as e:
        push("parse", "Package parsed safely", FAIL, str(e))
        return checks, "unknown", 0, 0

    manifest_bytes = files.get("manifest.json")
    if manifest_bytes is None:
        push("manifest", "Manifest present", FAIL, "manifest.json missing")
        return checks, "unknown", 0, 0
    push("manifest", "Manifest present", PASS, "manifest.json found")

    try:
        manifest = js_loads(manifest_bytes.decode("utf-8"))
        if manifest.get("format") != "lawcribs-matter-passport":
            raise ValueError("wrong format tag")
        if not isinstance(manifest.get("records"), list):
            raise ValueError("records is not an array")
        push("schema", "Manifest schema valid", PASS,
             f"formatVersion {manifest.get('formatVersion')}, scope {manifest.get('scope', {}).get('type')}")
        proto = manifest.get("protocol")
        if proto and proto.get("maintainer"):
            push("protocol", "Protocol steward", INFO,
                 f"{proto.get('name')} - maintained by {proto.get('maintainer')}")
    except Exception as e:
        push("schema", "Manifest schema valid", FAIL, str(e))
        return checks, "unknown", 0, 0

    scope = manifest.get("scope", {}).get("type", "unknown")
    records = manifest["records"]

    seen = set()
    digest_fails = digest_skipped = 0
    for rec in records:
        rid = rec.get("recordId")
        if rid in seen:
            push("records", "Record digests match", FAIL, f"duplicate recordId {rid}")
            return checks, scope, len(records), 0
        seen.add(rid)
        content = files.get(rec.get("contentLocation") or f"records/{rid}/content.bin")
        if content is None:
            digest_skipped += 1
            continue
        if sha256b64(content) != rec.get("digest", {}).get("value"):
            digest_fails += 1
    if digest_fails:
        push("records", "Record digests match", FAIL, f"{digest_fails} of {len(records)} records fail digest")
    elif digest_skipped:
        push("records", "Record digests match", WARN,
             f"{digest_skipped} records not included in package (scope: {scope})")
    else:
        push("records", "Record digests match", PASS, f"all {len(records)} record digests match")

    event_digests = []
    parsed_events = []
    events_bytes = files.get("events/events.jsonl")
    event_count = 0
    if events_bytes is not None:
        lines = [l for l in events_bytes.decode("utf-8").split("\n") if l.strip()]
        event_count = len(lines)
        chain_ok = True
        prev = None
        er = manifest.get("eventRange") or {}
        seq = er.get("fromSequence", 1) - 1
        for line in lines:
            seq += 1
            try:
                ev = js_loads(line)
            except Exception:
                chain_ok = False
                break
            if ev.get("sequenceNumber") != seq or ev.get("previousEventDigest") != prev:
                chain_ok = False
                break
            payload_digest = sha256b64(js_dumps(ev.get("payload")))
            recomputed = sha256b64(f"{ev.get('sequenceNumber')}|{ev.get('eventType')}|{ev.get('previousEventDigest') or ''}|{payload_digest}")
            if recomputed != ev.get("eventDigest") or payload_digest != ev.get("payloadDigest"):
                chain_ok = False
                break
            parsed_events.append(ev)
            event_digests.append(ev["eventDigest"])
            prev = ev["eventDigest"]
        push("events", "Event chain intact",
             PASS if chain_ok else FAIL,
             f"{event_count} events, chain and digests consistent" if chain_ok else f"chain broken at sequence {seq}")
        if er:
            expected = er.get("toSequence", 0) - er.get("fromSequence", 1) + 1
            if (expected != event_count or er.get("fromSequence", 1) > er.get("toSequence", 0)
                    or er.get("fromSequence", 1) < 1):
                push("eventrange", "Event range matches manifest", FAIL,
                     f"manifest declares {er.get('fromSequence')}-{er.get('toSequence')} ({expected} events), file has {event_count}")
    else:
        push("events", "Event chain intact", WARN, "no event file in package")

    if manifest.get("integrity", {}).get("merkleRoot"):
        root = merkle_root([r.get("digest", {}).get("value", "") for r in records] + event_digests)
        ok = root == manifest["integrity"]["merkleRoot"]
        push("merkle", "Merkle root matches signed manifest", PASS if ok else FAIL,
             f"root {manifest['integrity']['merkleRoot'][:20]}... recomputed" if ok
             else "recomputed root differs - package contents were altered after signing")

    ai_outputs = manifest.get("aiOutputs") or []
    if ai_outputs:
        verified = referenced = broken = 0
        for ai in ai_outputs:
            rid = ai.get("recordId")
            slice_bytes = files.get(f"provenance/{rid}.json")
            if slice_bytes is None:
                referenced += 1
                continue
            try:
                sl = js_loads(slice_bytes.decode("utf-8"))
                chain = sl.get("records") or []
                anchors = sl.get("anchors") or []
                ok = True
                seq = 0
                for rec in chain:
                    seq += 1
                    if rec.get("sequence") != seq or not rec.get("outputHash"):
                        ok = False
                        break
                ref = ai.get("provenanceRef", "")
                if ok and ref.startswith("lc-provenance-v1:"):
                    expected_ref = ref[len("lc-provenance-v1:"):]
                    ups = ai.get("upToSequence")
                    if ups is not None and (ups < 1 or ups > len(chain)):
                        ok = False
                    else:
                        prefix = chain[: ups if ups is not None else len(chain)]
                        joined = "".join(r.get("hash") or "" for r in prefix)
                        hex_digest = hashlib.sha256(joined.encode("utf-8")).hexdigest()
                        anchor_roots = [a.get("merkleRoot") for a in anchors if a.get("merkleRoot")]
                        ok = expected_ref in anchor_roots or expected_ref == hex_digest
                if ok:
                    verified += 1
                else:
                    broken += 1
            except Exception:
                broken += 1
        if broken:
            push("aiprovenance", "AI provenance", FAIL, f"{broken} provenance slice(s) malformed or inconsistent")
        elif verified:
            push("aiprovenance", "AI provenance", PASS,
                 f"{verified} generation chain(s) verified in package" + (f", {referenced} referenced only" if referenced else ""))
        else:
            push("aiprovenance", "AI provenance", INFO,
                 f"{referenced} AI output(s) reference provenance not embedded in the package")

    sig_bytes = files.get("signatures/manifest-signature.json")
    if sig_bytes is not None:
        try:
            sig = js_loads(sig_bytes.decode("utf-8"))
            canonical = canonicalize(manifest)
            ok = ec_verify(sig.get("publicKeyJwk", {}), sig.get("signatureValue", ""), canonical.encode("utf-8"))
            push("signature", "Manifest signature valid", PASS if ok else FAIL,
                 f"ES256 signature by key {sig.get('keyId')}" if ok else "signature does not verify")
            push("identity", "Signer identity independently established", INFO,
                 "signature proves key possession only; signer identity requires separate evidence")
            key_events = [e for e in parsed_events
                          if e.get("eventType") in ("key.registered", "key.rotated")]
            if key_events:
                in_chain = any((e.get("payload") or {}).get("keyId") == sig.get("keyId") for e in key_events)
                push("keylineage", "Signing key registered in chain", PASS if in_chain else WARN,
                     "signature key appears in the event chain's key lifecycle" if in_chain
                     else "signature key does not appear in the chain's key events")
            else:
                push("keylineage", "Signing key registered in chain", INFO,
                     "no key lifecycle events in package - manifest predates key lineage tracking")
            push("keystatus", "Signing key status", INFO,
                 "revocation state is not verifiable from the package alone - hosted verification reports live key status from the directory")
        except Exception as e:
            push("signature", "Manifest signature valid", FAIL, str(e))
    else:
        push("signature", "Manifest signature valid", WARN, "no signature file in package")

    if manifest.get("previousSnapshotDigest"):
        push("lineage", "Snapshot lineage", INFO,
             f"manifest declares a link to prior snapshot {manifest.get('previousSnapshotId', 'unknown')} - verifiable against an earlier package")
    push("timestamp", "Timestamp assurance", INFO,
         "timestamps are client-reported; check hosted verification for relay-anchored digest timestamps")
    if scope != "full":
        push("scope", "Package scope", INFO, f"package contains {scope} records and is not a complete matter record")

    return checks, scope, len(records), event_count


def cmd_package(path, expected_dir):
    checks, scope, record_count, event_count = verify_package(path)
    # Expected-report and totals drift are gate failures too - a printed
    # FAIL that exits 0 would let CI stay green on a broken fixture.
    problems = sum(1 for c in checks if c["status"] == FAIL)
    if expected_dir is None:
        expected_dir = str(Path(path).parent)
    exp_path = Path(expected_dir) / "expected-report.json"
    if exp_path.exists():
        exp = js_loads(exp_path.read_text(encoding="utf-8"))
        want = {c["id"]: c["status"] for c in exp.get("checks", [])}
        got = {c["id"]: c["status"] for c in checks}
        mismatches = []
        for cid, status in want.items():
            if got.get(cid) != status:
                mismatches.append(f"{cid}: expected {status}, got {got.get(cid, 'absent')}")
        extra = [cid for cid in got if cid not in want]
        if extra:
            mismatches.append(f"unexpected checks emitted: {', '.join(sorted(extra))}")
        if mismatches:
            out(FAIL, "Expected report match", "; ".join(mismatches))
            problems += 1
        else:
            out(PASS, "Expected report match", f"all {len(want)} expected checks match")
        if record_count != exp.get("recordCount") or event_count != exp.get("eventCount") or scope != exp.get("scope"):
            out(FAIL, "Report totals", f"expected records={exp.get('recordCount')} events={exp.get('eventCount')} scope={exp.get('scope')}, got records={record_count} events={event_count} scope={scope}")
            problems += 1
        else:
            out(PASS, "Report totals", f"records={record_count} events={event_count} scope={scope}")
    return 1 if problems else 0


def cmd_receipt(path):
    receipt = js_loads(Path(path).read_text(encoding="utf-8"))
    payload = receipt.get("payload") or {}
    shape_ok = (receipt.get("algorithm") == "ES256"
                and payload.get("version") == "lc-transfer-receipt-v1"
                and payload.get("decision") in ("accepted", "declined")
                and all(isinstance(payload.get(k), str) for k in
                        ("tokenHash", "snapshotId", "manifestDigest", "createdAt")))
    if not shape_ok:
        out(FAIL, "Receipt shape", "missing required fields or wrong version/decision")
        return 1
    out(PASS, "Receipt shape", f"lc-transfer-receipt-v1 decision={payload['decision']}")
    canonical = canonicalize(payload)
    ok = ec_verify(receipt.get("publicKeyJwk", {}), receipt.get("signatureValue", ""), canonical.encode("utf-8"))
    out(PASS if ok else FAIL, "Receipt signature",
        f"ES256 over canonical payload, keyFingerprint {receipt.get('keyFingerprint', '?')[:16]}..." if ok else "signature does not verify")
    out(INFO, "Receipt bindings", f"tokenHash={payload['tokenHash'][:16]}... snapshotId={payload['snapshotId']} manifestDigest={payload['manifestDigest'][:16]}... - compare against the transfer and package you hold")
    out(INFO, "Receipt assurance", "proves key possession and acknowledgement of these exact bytes; not legal identity, timestamp is client-reported")
    return 0 if ok else 1


def cmd_vectors(vdir):
    failures = 0
    vdir = Path(vdir)

    data = js_loads((vdir / "canonicalization.json").read_text(encoding="utf-8"))
    for v in data["vectors"]:
        try:
            ok = canonicalize(v["input"]) == v["canonical"] and sha256b64(v["canonical"]) == v["sha256"]
        except Exception as e:
            ok = False
            v["canonical"] = f"ERROR: {e}"
        out(PASS if ok else FAIL, f"canonicalization: {v['name']}", v.get("canonical", "")[:60])
        failures += 0 if ok else 1

    data = js_loads((vdir / "merkle.json").read_text(encoding="utf-8"))
    root = merkle_root(data["leaves"])
    ok = root == data["root"]
    out(PASS if ok else FAIL, "merkle: root", f"{root[:24]}...")
    failures += 0 if ok else 1
    for proof in data["proofs"]:
        leaf = data["leaves"][proof["leafIndex"]]
        ok = verify_merkle_proof(leaf, proof)
        out(PASS if ok else FAIL, f"merkle: proof leaf {proof['leafIndex']}", "" if ok else "proof rejected")
        failures += 0 if ok else 1
        ok = not verify_merkle_proof("foreign-leaf-not-in-tree", proof)
        out(PASS if ok else FAIL, f"merkle: foreign leaf {proof['leafIndex']}", "" if ok else "foreign leaf accepted")
        failures += 0 if ok else 1

    data = js_loads((vdir / "event-digest.json").read_text(encoding="utf-8"))
    for ev in data["events"]:
        pd = sha256b64(js_dumps(ev["payload"]))
        ok = pd == ev["payloadDigest"]
        out(PASS if ok else FAIL, f"event: payloadDigest seq {ev['sequenceNumber']}", "" if ok else f"got {pd}")
        failures += 0 if ok else 1
        ed = sha256b64(f"{ev['sequenceNumber']}|{ev['eventType']}|{ev.get('previousEventDigest') or ''}|{pd}")
        ok = ed == ev["eventDigest"]
        out(PASS if ok else FAIL, f"event: eventDigest seq {ev['sequenceNumber']}", "" if ok else f"got {ed}")
        failures += 0 if ok else 1

    data = js_loads((vdir / "transfer-envelope.json").read_text(encoding="utf-8"))
    try:
        key = b64url_decode(data["key"]["k"])
        env = data["envelope"]
        iv = base64.b64decode(env["iv"])
        blob = base64.b64decode(env["data"])
        plain = aes_gcm_decrypt(key, iv, blob)
        expected = base64.b64decode(data["plaintextBase64"])
        ok = plain == expected
        out(PASS if ok else FAIL, "transfer-envelope: AES-256-GCM decrypt", "" if ok else "plaintext mismatch")
    except Exception as e:
        ok = False
        out(FAIL, "transfer-envelope: AES-256-GCM decrypt", str(e))
    failures += 0 if ok else 1

    # Negative: a flipped tag byte must fail.
    try:
        bad = bytearray(base64.b64decode(data["envelope"]["data"]))
        bad[-1] ^= 1
        aes_gcm_decrypt(key, iv, bytes(bad))
        out(FAIL, "transfer-envelope: tampered tag rejected", "tampered ciphertext accepted")
        failures += 1
    except ValueError:
        out(PASS, "transfer-envelope: tampered tag rejected", "")

    return 1 if failures else 0


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 2
    cmd = args[0]
    if cmd == "package" and len(args) >= 2:
        expected = None
        if "--expected" in args:
            i = args.index("--expected")
            expected = args[i + 1]
        return cmd_package(args[1], expected)
    if cmd == "receipt" and len(args) >= 2:
        return cmd_receipt(args[1])
    if cmd == "vectors" and len(args) >= 2:
        return cmd_vectors(args[1])
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
