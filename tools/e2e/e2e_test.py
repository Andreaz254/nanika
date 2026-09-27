#!/usr/bin/env python3
"""
End-to-end test of the Java PacketEngine against the REAL Linux kernel TCP/UDP stack.
Needs root (creates a TUN device). Usage: python3 e2e_test.py <dir-with-compiled-classes>
"""
import fcntl, os, random, socket, struct, subprocess, sys, threading, time, hashlib
LOSS = float(os.environ.get('LOSS', '0'))   # e.g. LOSS=0.02 drops 2% of packets in each direction
BIG = int(float(os.environ.get('BIG_MB', '8')) * 1024 * 1024)

CLASSES = sys.argv[1]
HARNESS = sys.argv[2]
IFF_TUN, IFF_NO_PI = 0x0001, 0x1000

# ---------------------------------------------------------------- TUN device
tun = os.open('/dev/net/tun', os.O_RDWR)
fcntl.ioctl(tun, 0x400454ca, struct.pack('16sH', b'tunE2E', IFF_TUN | IFF_NO_PI))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
def sin(ip): return struct.pack('H2s4s8s', socket.AF_INET, b'\0\0', socket.inet_aton(ip), b'\0'*8)
fcntl.ioctl(s, 0x8916, struct.pack('16s16s', b'tunE2E', sin('10.0.0.1')))      # SIOCSIFADDR
fcntl.ioctl(s, 0x891c, struct.pack('16s16s', b'tunE2E', sin('255.255.255.0')))  # SIOCSIFNETMASK
fcntl.ioctl(s, 0x8922, struct.pack('16sI', b'tunE2E', 1500))                    # SIOCSIFMTU
flags = fcntl.ioctl(s, 0x8913, struct.pack('16sH', b'tunE2E', 0))               # SIOCGIFFLAGS
fl = struct.unpack('16sH', flags[:18])[1] | 0x1 | 0x40                           # UP|RUNNING
fcntl.ioctl(s, 0x8914, struct.pack('16sH', b'tunE2E', fl))                      # SIOCSIFFLAGS

# ---------------------------------------------------------------- test servers (the fake "internet")
PATTERN = bytes((i * 131 + 7) & 0xFF for i in range(65536))
def pattern(n): return (PATTERN * (n // 65536 + 1))[:n]

def recv_line(c):
    b = b''
    while not b.endswith(b'\n'):
        x = c.recv(1)
        if not x: break
        b += x
    return b.decode().strip()

def handle(c):
    try:
        cmd = recv_line(c).split()
        if cmd[0] == 'DOWN':
            c.sendall(pattern(int(cmd[1])))
        elif cmd[0] == 'UP':
            n, h = int(cmd[1]), hashlib.sha256()
            while n > 0:
                d = c.recv(min(65536, n))
                if not d: break
                h.update(d); n -= len(d)
            c.sendall((h.hexdigest() + '\n').encode())
        elif cmd[0] == 'ECHO':
            while True:
                d = c.recv(65536)
                if not d: break
                c.sendall(d)
        elif cmd[0] == 'SLOWREAD':       # sends a lot while client reads slowly -> exercises window handling
            c.sendall(pattern(int(cmd[1])))
    except Exception as e:
        print('server error', e, file=sys.stderr)
    finally:
        c.close()

def serve(port, first=None):
    ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(('127.0.0.1', port)); ls.listen(128)
    def loop():
        while True:
            c, _ = ls.accept()
            if first:
                c.sendall(first); c.close(); continue
            threading.Thread(target=handle, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()

serve(18080)
serve(18081, first=b'HELLO-FROM-SERVER\n')

def dns_server():
    ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(('127.0.0.1', 15353)); ls.listen(8)
    stats = {'conns': 0}
    def serve_conn(c):
        stats['conns'] += 1
        buf = b''
        while True:
            d = c.recv(4096)
            if not d: break
            buf += d
            while len(buf) >= 2:
                n = struct.unpack('!H', buf[:2])[0]
                if len(buf) < 2 + n: break
                q, buf = buf[2:2+n], buf[2+n:]
                # question end
                p = 12
                while q[p] != 0: p += 1 + q[p]
                qend = p + 5
                r = bytearray(q[:qend])
                r[2:4] = b'\x81\x80'; r[6:8] = b'\x00\x01'; r[8:12] = b'\0\0\0\0'
                r += b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04' + socket.inet_aton('93.184.216.34')
                c.sendall(struct.pack('!H', len(r)) + bytes(r))
    def loop():
        while True:
            c, _ = ls.accept()
            threading.Thread(target=serve_conn, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()
    return stats
dns_stats = dns_server()

# ---------------------------------------------------------------- start the engine and bridge it to the TUN
# E2E_HARNESS_CLASS / E2E_HARNESS_ARGS / E2E_CLASSPATH_EXTRA let tools/ssh/run_ssh_engine_e2e.sh run the same checks
# with a different upstream connector (default: the plain-socket harness).
proc = subprocess.Popen(
    ['java', '-cp', CLASSES + ':' + HARNESS + os.environ.get('E2E_CLASSPATH_EXTRA', ''),
     os.environ.get('E2E_HARNESS_CLASS', 'E2EHarness'),
     '10.0.0.50:80=127.0.0.1:18080', '10.0.0.52:80=127.0.0.1:18081', '8.8.8.8:53=127.0.0.1:15353']
    + os.environ.get('E2E_HARNESS_ARGS', '').split(),
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=open('/tmp/e2e_engine.log', 'wb'))

def tun_to_java():
    while True:
        try: pkt = os.read(tun, 65535)
        except OSError: return
        if LOSS and random.random() < LOSS: continue
        try:
            proc.stdin.write(struct.pack('!I', len(pkt)) + pkt); proc.stdin.flush()
        except Exception: return
def java_to_tun():
    while True:
        h = proc.stdout.read(4)
        if len(h) < 4: return
        n = struct.unpack('!I', h)[0]
        pkt = proc.stdout.read(n)
        if LOSS and random.random() < LOSS: continue
        try: os.write(tun, pkt)
        except OSError: pass
threading.Thread(target=tun_to_java, daemon=True).start()
threading.Thread(target=java_to_tun, daemon=True).start()
time.sleep(1.0)

# ---------------------------------------------------------------- tests
results = []
def check(name, ok, detail=''):
    ok = bool(ok)
    results.append(ok)
    print(('PASS ' if ok else 'FAIL ') + name + (' - ' + detail if detail else ''), flush=True)

def conn(ip='10.0.0.50', port=80, timeout=20):
    c = socket.socket(); c.settimeout(timeout); c.connect((ip, port)); return c

def read_all(c):
    out = []
    while True:
        d = c.recv(1 << 16)
        if not d: break
        out.append(d)
    return b''.join(out)

try:
    # 1. small download + server FIN
    c = conn(); c.sendall(b'DOWN 1000\n'); d = read_all(c); c.close()
    check('small download (1000 B, then server FIN)', d == pattern(1000), 'got %d' % len(d))

    # 2. large download
    N = BIG
    t0 = time.time(); c = conn(); c.sendall(b'DOWN %d\n' % N); d = read_all(c); c.close(); dt = time.time() - t0
    check('large download integrity', d == pattern(N), '%d bytes, %.1f MB/s' % (len(d), N / dt / 1e6))

    # 3. large upload
    N = BIG
    t0 = time.time(); c = conn(); c.sendall(b'UP %d\n' % N); c.sendall(pattern(N))
    reply = recv_line(c); c.close(); dt = time.time() - t0
    check('large upload integrity', reply == hashlib.sha256(pattern(N)).hexdigest(), '%.1f MB/s' % (N / dt / 1e6))

    # 4. echo with client half-close (FIN handling both directions)
    N = 2 * 1024 * 1024
    c = conn(); c.sendall(b'ECHO\n')
    data = pattern(N)
    def send_all():
        c.sendall(data); c.shutdown(socket.SHUT_WR)
    threading.Thread(target=send_all, daemon=True).start()
    d = read_all(c); c.close()
    check('echo 2 MiB with client half-close', d == data, 'got %d' % len(d))

    # 5. many parallel connections
    errs = []
    def worker(i):
        try:
            c = conn(); n = 200000 + i * 1000
            c.sendall(b'DOWN %d\n' % n); d = read_all(c); c.close()
            if d != pattern(n): errs.append(('mismatch', i, len(d)))
        except Exception as e: errs.append((i, repr(e)))
    ts = [threading.Thread(target=worker, args=(i,)) for i in range(60)]
    [t.start() for t in ts]; [t.join(60) for t in ts]
    check('60 parallel downloads', not errs, str(errs[:3]))

    # 6. connection refused (upstream cannot connect) -> RST -> ECONNREFUSED
    try:
        conn('10.0.0.51', 80, timeout=8); check('refused connect gives ECONNREFUSED', False, 'connected?!')
    except ConnectionRefusedError:
        check('refused connect gives ECONNREFUSED', True)
    except Exception as e:
        check('refused connect gives ECONNREFUSED', False, repr(e))

    # 7. server speaks first
    c = conn('10.0.0.52', 80); d = read_all(c); c.close()
    check('server-speaks-first banner', d == b'HELLO-FROM-SERVER\n', repr(d))

    # 8. slow reader (small receive buffer, big transfer) -> exercises the peer window / zero window
    N = 6 * 1024 * 1024
    c = socket.socket(); c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192); c.settimeout(60); c.connect(('10.0.0.50', 80))
    c.sendall(b'SLOWREAD %d\n' % N)
    got = bytearray(); t0 = time.time()
    while len(got) < N:
        d = c.recv(4096)
        if not d: break
        got += d
        if len(got) < 300000: time.sleep(0.001)
    c.close()
    check('slow reader / small window 6 MiB integrity', bytes(got) == pattern(N), 'got %d' % len(got))

    # 9. DNS over UDP -> DNS-over-TCP upstream
    def dns_query(name, qtype, qid, dst='10.0.0.2'):
        q = struct.pack('!HHHHHH', qid, 0x0100, 1, 0, 0, 0)
        for l in name.split('.'): q += bytes([len(l)]) + l.encode()
        q += b'\0' + struct.pack('!HH', qtype, 1)
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(1.5)
        for attempt in range(4):                      # like a real resolver: UDP is retried by the app
            u.sendto(q, (dst, 53))
            try:
                r, _ = u.recvfrom(4096); u.close(); return r
            except socket.timeout:
                continue
        raise socket.timeout('no DNS answer after 4 tries')
    r = dns_query('example.com', 1, 0x1234)
    ok = struct.unpack('!H', r[:2])[0] == 0x1234 and r[-4:] == socket.inet_aton('93.184.216.34')
    check('DNS A query answered through tunnel (id preserved)', ok, r.hex()[:40])
    r = dns_query('example.com', 28, 0x4321)
    an = struct.unpack('!H', r[6:8])[0]; rcode = r[3] & 0xF
    check('AAAA query suppressed (NOERROR, 0 answers)', an == 0 and rcode == 0 and bool(r[2] & 0x80))

    # 10. 40 concurrent DNS queries, same IDs from different sockets -> internal id remapping must keep them apart
    derrs = []
    def dworker(i):
        try:
            r = dns_query('example.com', 1, 0x7777)          # deliberately identical DNS id everywhere
            if struct.unpack('!H', r[:2])[0] != 0x7777 or r[-4:] != socket.inet_aton('93.184.216.34'):
                derrs.append(i)
        except Exception as e: derrs.append((i, repr(e)))
    ts = [threading.Thread(target=dworker, args=(i,)) for i in range(40)]
    [t.start() for t in ts]; [t.join(30) for t in ts]
    check('40 concurrent DNS queries with identical IDs', not derrs, str(derrs[:3]))
    check('DNS used ONE persistent upstream connection', dns_stats['conns'] == 1, 'upstream conns=%d' % dns_stats['conns'])
except Exception as e:
    import traceback; traceback.print_exc()
    check('unexpected exception', False, repr(e))

time.sleep(5)    # let linger timers fire, then confirm no flow leaks
proc.stdin.close(); proc.wait(10)
log = open('/tmp/e2e_engine.log').read()
leak = [l for l in log.splitlines() if 'flows at exit' in l]
print(leak[0] if leak else 'no exit line')
check('no flow leak after all tests', bool(leak) and leak[0].endswith(': 0'), leak[0] if leak else '')
print()
print('%d/%d checks passed' % (sum(results), len(results)))
sys.exit(0 if all(results) else 1)
