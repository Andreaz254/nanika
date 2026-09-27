#!/usr/bin/env python3
"""Test rig for the SSH protocol: a real SSH server (paramiko, password login, direct-tcpip forwarding)
behind HTTP-upgrade / WebSocket front ends, like the servers used with this kind of app.

  plain  :  GET ... Upgrade: websocket  ->  101  -> raw SSH           (no SNI, "port 80" style)
  tls    :  same, inside TLS, records the SNI seen                    ("port 443" style)
  double :  200 Connection established + 101 in a row, then raw SSH
  framed :  real RFC 6455 frames both ways (pings injected, payloads split into several frames)
  A request without 'Upgrade: websocket' gets 403.
Writes <dir>/ports.json when ready.   Control port: KILL | SNI | REQ <name> | QUIT
"""
import base64, hashlib, json, os, random, socket, ssl, struct, subprocess, sys, threading, time
import paramiko

USER, PASS = "tester", "s3cret"
GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
state = {"sni": [], "req": {}, "transports": []}


# ------------------------------------------------------------------ SSH server (real sshd behaviour for tunnels)
class Srv(paramiko.ServerInterface):
    def __init__(self, dests): self.dests = dests
    def get_allowed_auths(self, u): return "password"
    def check_auth_password(self, u, p):
        return paramiko.AUTH_SUCCESSFUL if (u, p) == (USER, PASS) else paramiko.AUTH_FAILED
    def check_channel_request(self, kind, chanid): return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        try:
            s = socket.create_connection(destination, timeout=5)
        except OSError:
            return paramiko.OPEN_FAILED_CONNECT_FAILED
        self.dests[chanid] = s
        return paramiko.OPEN_SUCCEEDED


def pump(ch, s):
    def a():
        try:
            while True:
                d = s.recv(65536)
                if not d: break
                ch.sendall(d)
        except Exception: pass
        try: ch.shutdown_write()
        except Exception: pass
    def b():
        try:
            while True:
                d = ch.recv(65536)
                if not d: break
                s.sendall(d)
        except Exception: pass
        try: s.shutdown(socket.SHUT_WR)
        except Exception: pass
    ta, tb = threading.Thread(target=a, daemon=True), threading.Thread(target=b, daemon=True)
    ta.start(); tb.start(); ta.join(); tb.join()
    for x in (ch, s):
        try: x.close()
        except Exception: pass


def ssh_conn(sock, hostkey):
    t = paramiko.Transport(sock)
    t.add_server_key(hostkey)
    dests = {}
    state["transports"].append(t)
    try: t.start_server(server=Srv(dests))
    except Exception: return
    while t.is_active():
        ch = t.accept(1)
        if ch is None: continue
        s = dests.pop(ch.get_id(), None)
        if s is None: ch.close(); continue
        threading.Thread(target=pump, args=(ch, s), daemon=True).start()


def listen(port=0):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port)); s.listen(128); return s


def accept_loop(ls, fn, *args):
    while True:
        try: c, _ = ls.accept()
        except OSError: return
        threading.Thread(target=fn, args=(c,) + args, daemon=True).start()


# ------------------------------------------------------------------ echo target
def echo(c):
    try:
        while True:
            d = c.recv(65536)
            if not d: break
            c.sendall(d)
    except Exception: pass
    c.close()


# ------------------------------------------------------------------ WebSocket helpers
def recv_exact(c, n, buf):
    while len(buf) < n:
        d = c.recv(65536)
        if not d: raise EOFError
        buf += d
    return buf[:n], buf[n:]

def read_frame(c, buf):
    h, buf = recv_exact(c, 2, buf)
    op, ln, masked = h[0] & 0x0F, h[1] & 0x7F, h[1] & 0x80
    if ln == 126: x, buf = recv_exact(c, 2, buf); ln = struct.unpack(">H", x)[0]
    elif ln == 127: x, buf = recv_exact(c, 8, buf); ln = struct.unpack(">Q", x)[0]
    m = b""
    if masked: m, buf = recv_exact(c, 4, buf)
    p, buf = recv_exact(c, ln, buf)
    if masked: p = bytes(b ^ m[i & 3] for i, b in enumerate(p))
    return op, p, buf, bool(masked)

def frame(op, p):
    n = len(p)
    hd = bytes([0x80 | op])
    if n < 126: hd += bytes([n])
    elif n < 65536: hd += bytes([126]) + struct.pack(">H", n)
    else: hd += bytes([127]) + struct.pack(">Q", n)
    return hd + p


def front(c, mode, ctx, ssh_port, name):
    try:
        if ctx: c = ctx.wrap_socket(c, server_side=True)
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = c.recv(4096)
            if not d: return
            buf += d
        head, rest = buf.split(b"\r\n\r\n", 1)
        state["req"][name] = head.decode("latin1")
        low = head.lower()
        if b"upgrade: websocket" not in low:
            c.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"); c.close(); return
        up = socket.create_connection(("127.0.0.1", ssh_port))
        if mode == "double":
            c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\nHTTP/1.1 101 Switching Protocols\r\n"
                      b"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
        elif mode == "framed":
            key = None
            for line in head.split(b"\r\n"):
                if line.lower().startswith(b"sec-websocket-key:"): key = line.split(b":", 1)[1].strip()
            if not key: c.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n"); c.close(); return
            acc = base64.b64encode(hashlib.sha1(key + GUID).digest())
            c.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                      b"Sec-WebSocket-Accept: " + acc + b"\r\n\r\n")
        else:
            c.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")

        if mode != "framed":
            if rest: up.sendall(rest)
            def a():
                try:
                    while True:
                        d = c.recv(65536)
                        if not d: break
                        up.sendall(d)
                except Exception: pass
                try: up.shutdown(socket.SHUT_WR)
                except Exception: pass
            threading.Thread(target=a, daemon=True).start()
            try:
                while True:
                    d = up.recv(65536)
                    if not d: break
                    c.sendall(d)
            except Exception: pass
            c.close(); up.close(); return

        lock = threading.Lock()
        def send(b):
            with lock: c.sendall(b)
        def a():                       # client frames (must be masked) -> ssh
            b = rest
            try:
                while True:
                    op, p, b, masked = read_frame(c, b)
                    if not masked: raise ValueError("client frame not masked")
                    if op in (0, 1, 2): up.sendall(p)
                    elif op == 9: send(frame(10, p))
                    elif op == 8: break
            except (EOFError, ConnectionError, OSError):
                pass                                   # client closed the connection: normal
            except Exception as e:
                state.setdefault("errors", []).append(repr(e))   # protocol violation (e.g. unmasked frame)
            try: up.shutdown(socket.SHUT_WR)
            except Exception: pass
        threading.Thread(target=a, daemon=True).start()
        send(frame(9, b"hi"))          # a ping right after the upgrade
        rnd = random.Random(7)
        try:
            while True:
                d = up.recv(65536)
                if not d: break
                i = 0
                while i < len(d):      # split into several frames of random size
                    n = rnd.choice([1, 7, 100, 1000, 70000])
                    send(frame(2, d[i:i + n])); i += n
        except Exception: pass
        try: send(frame(8, b""))
        except Exception: pass
        c.close(); up.close()
    except Exception as e:
        if mode == "framed" and not isinstance(e, (EOFError, ConnectionError, OSError)):
            state.setdefault("errors", []).append(repr(e))
        try: c.close()
        except Exception: pass


def control(c, tdir):
    f = c.makefile("rw")
    for line in f:
        cmd = line.strip().split(" ", 1)
        if cmd[0] == "KILL":
            for t in list(state["transports"]):
                try: t.close()
                except Exception: pass
            state["transports"].clear(); f.write("OK\n")
        elif cmd[0] == "SNI": f.write(json.dumps(state["sni"][-1:]) + "\n")
        elif cmd[0] == "REQ": f.write(json.dumps(state["req"].get(cmd[1], "")) + "\n")
        elif cmd[0] == "ERR": f.write(json.dumps(state.get("errors", [])) + "\n")
        elif cmd[0] == "QUIT": f.write("BYE\n"); f.flush(); os._exit(0)
        f.flush()


def main():
    tdir = sys.argv[1]
    os.makedirs(tdir, exist_ok=True)
    cert, key = os.path.join(tdir, "c.pem"), os.path.join(tdir, "k.pem")
    subprocess.check_call(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
                           "-days", "2", "-subj", "/CN=real-server.example"], stderr=subprocess.DEVNULL)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, key)
    ctx.sni_callback = lambda sock, name, c: state["sni"].append(name)
    hostkey = paramiko.ECDSAKey.generate(bits=256)

    ls_ssh, ls_echo = listen(), listen()
    threading.Thread(target=accept_loop, args=(ls_ssh, ssh_conn, hostkey), daemon=True).start()
    threading.Thread(target=accept_loop, args=(ls_echo, echo), daemon=True).start()
    ssh_port = ls_ssh.getsockname()[1]
    ports = {"ssh": ssh_port, "echo": ls_echo.getsockname()[1]}
    for name, mode, tls in (("plain", "raw", False), ("tls", "raw", True), ("double", "double", False),
                            ("framed", "framed", False), ("framedtls", "framed", True)):
        ls = listen()
        threading.Thread(target=accept_loop, args=(ls, front, mode, ctx if tls else None, ssh_port, name), daemon=True).start()
        ports[name] = ls.getsockname()[1]
    closed = listen(); ports["closed"] = closed.getsockname()[1]; closed.close()
    lc = listen(); ports["control"] = lc.getsockname()[1]
    threading.Thread(target=accept_loop, args=(lc, control, tdir), daemon=True).start()
    with open(os.path.join(tdir, "ports.json.tmp"), "w") as f: json.dump(ports, f)
    os.rename(os.path.join(tdir, "ports.json.tmp"), os.path.join(tdir, "ports.json"))
    while True: time.sleep(3600)

main()
