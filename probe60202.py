#!/usr/bin/env python3
"""Raw SOCKS5 reachability probe through Cloudflare WARP socks5 (127.0.0.1:40000).
Records SOCKS5 reply code + timing per target: distinguishes OPEN / REFUSED / UNREACH / TIMEOUT.
Also fetches minimal HTTP for interesting ports. Pure stdlib.
"""
import socket, struct, sys, time, json, os

PX_HOST = os.environ.get("PX_HOST", "127.0.0.1")
PX_PORT = int(os.environ.get("PX_PORT", "40000"))
TIMEOUT = float(os.environ.get("CONN_TIMEOUT", "12"))

# (label, ip, port)
TARGETS = [
    ("TARGET",   "51.79.66.166", 3000),
    ("TARGET",   "51.79.66.166", 8787),
    ("TARGET",   "51.79.66.166", 10051),
    ("TARGET",   "51.79.66.166", 80),
    ("TARGET",   "51.79.66.166", 443),
    ("TARGET",   "51.79.66.166", 22),
    ("TARGET",   "51.79.66.166", 9),      # near-certain closed on a live host
    ("CTRL-neigh22", "51.79.66.1", 22),
    ("CTRL-neigh80", "51.79.66.1", 80),
    ("CTRL-neigh100", "51.79.66.100", 80),
    ("CTRL-master", "40.160.50.80", 3000),
    ("CTRL-master80", "40.160.50.80", 80),
    ("CTRL-mysql", "40.160.21.1", 3306),
    ("CTRL-37",  "135.148.204.37", 3000),
    ("CTRL-refused", "127.0.0.1", 1),
]

REPLY = {0:"SUCCEEDED",1:"GENERAL_FAILURE",2:"NOT_ALLOWED",3:"NETWORK_UNREACHABLE",
         4:"HOST_UNREACHABLE",5:"CONNECTION_REFUSED",6:"TTL_EXPIRED",7:"CMD_NOT_SUPPORTED",
         8:"ATYP_NOT_SUPPORTED"}

def socks_connect(ip, port, timeout=TIMEOUT):
    t0=time.time()
    s=socket.socket(); s.settimeout(timeout)
    try:
        s.connect((PX_HOST, PX_PORT))
        s.sendall(b"\x05\x01\x00")
        r=s.recv(2)
        if len(r)<2 or r[0]!=5:
            return ("PROXY_GREET_FAIL", None, round((time.time()-t0)*1000)), None, s
        req=b"\x05\x01\x00\x01"+socket.inet_aton(ip)+struct.pack(">H",port)
        s.sendall(req)
        hdr=s.recv(4)
        if len(hdr)<4:
            return ("NO_REPLY_HEADER", None, round((time.time()-t0)*1000)), None, s
        rep=hdr[1]
        atyp=hdr[3]
        if atyp==1: s.recv(4)
        elif atyp==4: s.recv(16)
        elif atyp==3:
            ln=s.recv(1)[0]; s.recv(ln)
        s.recv(2)
        return (REPLY.get(rep, "REP_%d"%rep), rep, round((time.time()-t0)*1000)), s, s
    except socket.timeout:
        return ("TIMEOUT", None, round((time.time()-t0)*1000)), None, s
    except ConnectionRefusedError:
        return ("PROXY_CONN_REFUSED", None, round((time.time()-t0)*1000)), None, s
    except Exception as e:
        return ("ERR:%s"%type(e).__name__, None, round((time.time()-t0)*1000)), None, s

def http_get_via(s, host, port, path="/", extra=""):
    try:
        req=(f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: wrp60202\r\n"
             f"Accept: */*\r\nConnection: close\r\n{extra}\r\n").encode()
        s.settimeout(10); s.sendall(req)
        buf=b""
        while len(buf)<3000:
            d=s.recv(2000)
            if not d: break
            buf+=d
        return buf.decode("latin1","replace")
    except Exception as e:
        return "HTTPERR:%s"%type(e).__name__

def main():
    url = None
    print("=== WARP identity ===")
    # trace through proxy via curl-free raw HTTPS is complex; use requests-free approach:
    # use urllib with socks not available -> do simple TLS to cloudflare trace through socks
    try:
        import ssl
        st,s,_=socks_connect("1.1.1.1",443,timeout=10)
        print("socks to 1.1.1.1:443 ->",st)
        if s:
            ctx=ssl.create_default_context()
            ss=ctx.wrap_socket(s,server_hostname="www.cloudflare.com")
            ss.sendall(b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: www.cloudflare.com\r\nConnection: close\r\n\r\n")
            data=b""
            while True:
                d=ss.recv(2000)
                if not d: break
                data+=d
            body=data.split(b"\r\n\r\n",1)[-1].decode("latin1","replace")
            for line in body.splitlines():
                if line.startswith(("ip=","warp=","loc=","colo=")):
                    print("TRACE",line)
    except Exception as e:
        print("trace err",type(e).__name__,e)

    print("=== reachability ===")
    res=[]
    for label,ip,port in TARGETS:
        st,rep,ms=socks_connect(ip,port)
        rec={"label":label,"ip":ip,"port":port,"state":st,"rep":rep,"ms":ms}
        s=None
        # re-connect if succeeded to do HTTP
        if st=="SUCCEEDED":
            st2,s2,_=socks_connect(ip,port)
            if s2:
                try:
                    if label=="TARGET" and port in (3000,8787):
                        out=http_get_via(s2,ip,port,"/api/status")
                    elif label in ("CTRL-master","CTRL-37") and port==3000:
                        out=http_get_via(s2,ip,port,"/api/status")
                    elif port in (80,443):
                        out=http_get_via(s2,ip,port,"/")
                    elif port==22:
                        s2.settimeout(5); out=s2.recv(200).decode("latin1","replace")
                    else:
                        s2.settimeout(3); out="(raw connect only)"
                except Exception as e:
                    out="READERR:%s"%type(e).__name__
                rec["resp"]=out[:600]
                try: s2.close()
                except: pass
        print(json.dumps(rec,ensure_ascii=False))
        res.append(rec)
    json.dump(res, open("reachability.json","w"), ensure_ascii=False, indent=1)
    print("=== summary ===")
    for r in res:
        print(f'{r["label"]:14s} {r["ip"]}:{r["port"]:<6d} {r["state"]:<22s} {r["ms"]}ms')

if __name__=="__main__":
    main()