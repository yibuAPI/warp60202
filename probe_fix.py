#!/usr/bin/env python3
"""FIXED raw SOCKS5 reachability probe through Cloudflare WARP socks5 (127.0.0.1:40000).
Fixes the bug in probe60202.py (returned a socket object inside the record -> json.dumps
raised "Object of type socket is not JSON serializable", so NO record was ever written and
login60202.sh wrongly reported TARGET3000_REACHABLE=no).
Adds IPv4+IPv6 targets. Pure stdlib.
"""
import socket, struct, sys, time, json, os

PX_HOST = os.environ.get("PX_HOST", "127.0.0.1")
PX_PORT = int(os.environ.get("PX_PORT", "40000"))
TIMEOUT = float(os.environ.get("CONN_TIMEOUT", "12"))

# (label, addr, family, port)   family 4 or 6
TARGETS = [
    ("TARGET",   "51.79.66.166", 4, 3000),
    ("TARGET",   "51.79.66.166", 4, 8787),
    ("TARGET",   "51.79.66.166", 4, 10051),
    ("TARGET",   "51.79.66.166", 4, 80),
    ("TARGET",   "51.79.66.166", 4, 443),
    ("TARGET",   "51.79.66.166", 4, 22),
    ("TARGET",   "51.79.66.166", 4, 9),      # near-certain closed on a live host
    ("TARGET-v6", "2607:5300:205:200::6c1c", 6, 3000),
    ("TARGET-v6", "2607:5300:205:200::6c1c", 6, 8787),
    ("TARGET-v6", "2607:5300:205:200::6c1c", 6, 10051),
    ("TARGET-v6", "2607:5300:205:200::6c1c", 6, 22),
    ("CTRL-neigh22", "51.79.66.1", 4, 22),
    ("CTRL-neigh80", "51.79.66.1", 4, 80),
    ("CTRL-neigh100", "51.79.66.100", 4, 80),
    ("CTRL-master", "40.160.50.80", 4, 3000),
    ("CTRL-master80", "40.160.50.80", 4, 80),
    ("CTRL-mysql", "40.160.21.1", 4, 3306),
    ("CTRL-37",  "135.148.204.37", 4, 3000),
    ("CTRL-relay-v6", "2607:5300:205:200::6962", 6, 80),
    ("CTRL-relay-v6", "2607:5300:205:200::6962", 6, 3000),
    ("CTRL-refused", "127.0.0.1", 4, 1),
]

REPLY = {0:"SUCCEEDED",1:"GENERAL_FAILURE",2:"NOT_ALLOWED",3:"NETWORK_UNREACHABLE",
         4:"HOST_UNREACHABLE",5:"CONNECTION_REFUSED",6:"TTL_EXPIRED",7:"CMD_NOT_SUPPORTED",
         8:"ATYP_NOT_SUPPORTED"}

def pack_addr(addr, fam):
    if fam == 4:
        return b"\x01" + socket.inet_aton(addr)
    if fam == 6:
        return b"\x04" + socket.inet_pton(socket.AF_INET6, addr)
    # domain
    b = addr.encode()
    return b"\x03" + bytes([len(b)]) + b

def socks_connect(addr, fam, port, timeout=TIMEOUT):
    t0 = time.time()
    ms = lambda: round((time.time()-t0)*1000)
    s = socket.socket(); s.settimeout(timeout)
    try:
        s.connect((PX_HOST, PX_PORT))
        s.sendall(b"\x05\x01\x00")
        r = s.recv(2)
        if len(r) < 2 or r[0] != 5:
            return ("PROXY_GREET_FAIL", None, ms()), None
        s.sendall(b"\x05\x01\x00" + pack_addr(addr, fam) + struct.pack(">H", port))
        hdr = s.recv(4)
        if len(hdr) < 4:
            return ("NO_REPLY_HEADER", None, ms()), None
        rep = hdr[1]; atyp = hdr[3]
        if atyp == 1:
            s.recv(4)
        elif atyp == 4:
            s.recv(16)
        elif atyp == 3:
            ln = s.recv(1)
            if ln: s.recv(ln[0])
        s.recv(2)
        return (REPLY.get(rep, "REP_%d" % rep), rep, ms()), s
    except socket.timeout:
        return ("TIMEOUT", None, ms()), None
    except ConnectionRefusedError:
        return ("PROXY_CONN_REFUSED", None, ms()), None
    except Exception as e:
        return ("ERR:%s" % type(e).__name__, None, ms()), None
    finally:
        pass

def http_get_via(s, host, port, path="/"):
    try:
        req = ("GET %s HTTP/1.1\r\nHost: %s:%d\r\nUser-Agent: wrpfix\r\n"
               "Accept: */*\r\nConnection: close\r\n\r\n" % (path, host, port)).encode()
        s.settimeout(10); s.sendall(req)
        buf = b""
        while len(buf) < 3000:
            d = s.recv(2000)
            if not d: break
            buf += d
        return buf.decode("latin1", "replace")
    except Exception as e:
        return "HTTPERR:%s" % type(e).__name__

def main():
    print("=== reachability (FIXED) ===", flush=True)
    res = []
    for label, addr, fam, port in TARGETS:
        (state, rep, elapsed), s = socks_connect(addr, fam, port)
        rec = {"label": label, "ip": addr, "fam": fam, "port": port,
               "state": state, "rep": rep, "ms": elapsed}
        if state == "SUCCEEDED" and s is not None:
            if port in (3000, 8787, 10051):
                out = http_get_via(s, addr, port, "/api/status")
            elif port in (80, 443):
                out = http_get_via(s, addr, port, "/")
            elif port == 22:
                try:
                    s.settimeout(5); out = s.recv(200).decode("latin1", "replace")
                except Exception as e:
                    out = "READERR:%s" % type(e).__name__
            else:
                out = "(raw connect only)"
            rec["resp"] = out[:600]
        if s is not None:
            try: s.close()
            except Exception: pass
        print(json.dumps(rec, ensure_ascii=False), flush=True)
        res.append(rec)
    for fn in ("reachability_fix.json", "reachability.json"):
        try:
            json.dump(res, open(fn, "w"), ensure_ascii=False, indent=1)
        except Exception as e:
            print("write", fn, "err", e, flush=True)
    print("=== summary ===", flush=True)
    for r in res:
        print("%-16s %s:%s %-22s %sms" % (r["label"], r["ip"], r["port"], r["state"], r["ms"]), flush=True)

if __name__ == "__main__":
    main()