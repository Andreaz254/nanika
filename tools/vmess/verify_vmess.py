"""Independent (Python/cryptography) VMess-AEAD *server-side* implementation used to cross-check the Java codec.
Decrypts what Java produced, and builds a server response that Java must decode."""
import hashlib, hmac, struct, subprocess, sys, zlib, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class H:  # nested-HMAC "hash" object, mirrors Go's hmac.New(parent.Create, key)
    def __init__(self, parent, key): self.parent, self.key, self.buf = parent, key, b""
    block_size, digest_size, name = 64, 32, "vmesskdf"
    def update(self, d): self.buf += d
    def copy(self): c = H(self.parent, self.key); c.buf = self.buf; return c
    def digest(self):
        if self.parent is None: return hmac.new(self.key, self.buf, hashlib.sha256).digest()
        return hmac.new(self.key, self.buf, lambda d=b"": self.parent_hash(d)).digest()
    def parent_hash(self, d): pass

def make_hash(chain):
    # chain = list of keys, innermost first: [b"VMess AEAD KDF", p0, p1, ...]
    if len(chain) == 1:
        class B:
            block_size, digest_size, name = 64, 32, "b"
            def __init__(s, d=b""): s.h = hmac.new(chain[0], d, hashlib.sha256)
            def update(s, d): s.h.update(d)
            def copy(s): c = B(); c.h = s.h.copy(); return c
            def digest(s): return s.h.digest()
        return B
    inner = make_hash(chain[:-1])
    class C:
        block_size, digest_size, name = 64, 32, "c"
        def __init__(s, d=b""): s.h = hmac.new(chain[-1], b"", inner); s.h.update(d)
        def update(s, d): s.h.update(d)
        def copy(s): c = C(); c.h = s.h.copy(); return c
        def digest(s): return s.h.digest()
    return C

def kdf(key, *path):
    h = make_hash([b"VMess AEAD KDF"] + [p if isinstance(p, bytes) else p.encode() for p in path])()
    h.update(key); return h.digest()

def fnv1a(b):
    h = 0x811c9dc5
    for x in b: h = ((h ^ x) * 0x01000193) & 0xffffffff
    return h

uuid = bytes.fromhex("4224f5786c714cf2ae773cf1d8878fed")
cmdkey = hashlib.md5(uuid + b"c48619fe-8f02-49e0-b9e9-edf763e17e21").digest()
cp = ["java", "-cp", sys.argv[1], "VmessVectors"]
lines = dict(l.split(" ", 1) for l in subprocess.check_output(cp + ["dump"], text=True).splitlines())
raw = bytes.fromhex(lines["header"].strip())

# ---- server: parse request header
authid = raw[:16]
dec = Cipher(algorithms.AES(kdf(cmdkey, "AES Auth ID Encryption")[:16]), modes.ECB()).decryptor()
a = dec.update(authid) + dec.finalize()
ts, = struct.unpack(">Q", a[:8]); assert zlib.crc32(a[:12]) == struct.unpack(">I", a[12:])[0], "authid crc"
assert ts == 1760000000, ts
lenenc = raw[16:34]; nonce8 = raw[34:42]
n = struct.unpack(">H", AESGCM(kdf(cmdkey, "VMess Header AEAD Key_Length", authid, nonce8)[:16]).decrypt(
    kdf(cmdkey, "VMess Header AEAD Nonce_Length", authid, nonce8)[:12], lenenc, authid))[0]
hdr = AESGCM(kdf(cmdkey, "VMess Header AEAD Key", authid, nonce8)[:16]).decrypt(
    kdf(cmdkey, "VMess Header AEAD Nonce", authid, nonce8)[:12], raw[42:42 + n + 16], authid)
assert len(raw) == 42 + n + 16
assert hdr[0] == 1
iv, key, V, opt, pls, rsv, cmd = hdr[1:17], hdr[17:33], hdr[33], hdr[34], hdr[35], hdr[36], hdr[37]
port, atype = struct.unpack(">H", hdr[38:40])[0], hdr[40]
assert iv == bytes.fromhex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf") and key == bytes(range(16)) and V == 0x7b
assert opt == 1 and (pls & 15) == 3 and cmd == 1 and port == 443 and atype == 1 and hdr[41:45] == bytes([142, 250, 185, 46])
pad = pls >> 4; assert pad == 5
assert fnv1a(hdr[:-4]) == struct.unpack(">I", hdr[-4:])[0], "fnv"
assert len(hdr) == 45 + pad + 4
print("OK request header: ts/crc/AEAD/fields/padding/fnv all verified by independent implementation")

# ---- server: decrypt chunks
def chunk_nonce(iv, i): return struct.pack(">H", i) + iv[2:12]
body = b"".join(bytes.fromhex(lines[k].strip()) for k in ("chunk0", "chunk1", "chunk2"))
pos, i, out = 0, 0, []
while pos < len(body):
    sz, = struct.unpack(">H", body[pos:pos + 2]); ct = body[pos + 2:pos + 2 + sz]; pos += 2 + sz
    out.append(AESGCM(key).decrypt(chunk_nonce(iv, i), ct, None)); i += 1
assert out == [b"GET / HTTP/1.1\r\n\r\n", b"", b"\x01\x02\x03"], out
print("OK request chunks: sizes, nonce counter, GCM verified")

# ---- server: build response, Java must decode it
rk, riv = hashlib.sha256(key).digest()[:16], hashlib.sha256(iv).digest()[:16]
rh = bytes([V, 0, 0, 0])
resp = AESGCM(kdf(rk, "AEAD Resp Header Len Key")[:16]).encrypt(kdf(riv, "AEAD Resp Header Len IV")[:12], struct.pack(">H", len(rh)), None)
resp += AESGCM(kdf(rk, "AEAD Resp Header Key")[:16]).encrypt(kdf(riv, "AEAD Resp Header IV")[:12], rh, None)
payloads = [b"HTTP/1.1 200 OK\r\n\r\n", os.urandom(7900), b""]
for i, p in enumerate(payloads):
    ct = AESGCM(rk).encrypt(chunk_nonce(riv, i), p, None); resp += struct.pack(">H", len(ct)) + ct
res = subprocess.run(cp + ["decode"], input=resp.hex() + "\n", capture_output=True, text=True, check=True).stdout.splitlines()
want = (payloads[0] + payloads[1]).hex() + " eof=true"
for l in res:
    name, rest = l.split(" ", 1); assert rest == want, (name, rest[:60])
print("OK response: header + chunks + EOF decoded by Java (whole / 1-byte / 7-byte fragments)")
