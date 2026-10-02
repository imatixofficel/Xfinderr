"""Real transport/protocol probe for Xfinder.

The collector only publishes a config after a local SOCKS proxy backed by
Xray can reach a small HTTPS canary through that config.  Unsupported or
malformed URI variants are rejected instead of being labelled alive.
"""
from __future__ import annotations
import asyncio, base64, json, os, random, re, socket, tempfile, time
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

CANARY = os.getenv("XFINDER_CANARY", "https://www.gstatic.com/generate_204")
XRAY_BIN = os.getenv("XRAY_BIN", "xray")
PROBE_TIMEOUT = float(os.getenv("XRAY_PROBE_TIMEOUT", "10"))
CONCURRENCY = int(os.getenv("XRAY_CONCURRENCY", "24"))


def _b64decode(s: str) -> bytes:
    s = s.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * ((4 - len(s) % 4) % 4))


def _q(u):
    return {k: v[-1] for k, v in parse_qs(urlparse(u).query, keep_blank_values=True).items()}


def _stream(q):
    net = q.get("type", q.get("network", "tcp")).lower()
    s = {"network": net}
    sec = q.get("security", "")
    if sec == "tls":
        tls = {"serverName": q.get("sni") or q.get("host", ""),
               "allowInsecure": q.get("allowInsecure", q.get("insecure", "0")) in {"1", "true"}}
        if q.get("alpn"): tls["alpn"] = [x for x in q["alpn"].split(",") if x]
        if q.get("fp"): tls["fingerprint"] = q["fp"]
        s["security"] = "tls"; s["tlsSettings"] = tls
    elif sec == "reality":
        rs = {"serverName": q.get("sni", ""), "fingerprint": q.get("fp", "chrome"),
              "publicKey": q.get("pbk", ""), "shortId": q.get("sid", "")}
        s["security"] = "reality"; s["realitySettings"] = rs
    if net == "ws":
        s["wsSettings"] = {"path": unquote(q.get("path", "/")),
                            "headers": ({"Host": q["host"]} if q.get("host") else {})}
    elif net == "grpc":
        s["grpcSettings"] = {"serviceName": q.get("serviceName", q.get("serviceName", "")),
                              "multiMode": q.get("mode", "") == "multi"}
    elif net == "http":
        s["httpSettings"] = {"path": unquote(q.get("path", "/")),
                              "host": [q["host"]] if q.get("host") else []}
    elif net not in {"tcp", "kcp", "quic", "httpupgrade", "xhttp"}:
        return None
    return s


def to_xray(cfg: str) -> dict | None:
    proto = cfg.split("://", 1)[0].lower()
    try:
        u = urlparse(cfg)
        q = _q(cfg)
        host, port = u.hostname, u.port
        if proto == "vless":
            if not host or not port: return None
            stream = _stream(q)
            if stream is None: return None

            uid = unquote(u.username or "")
            if not uid: return None
            user = {"id": uid, "encryption": q.get("encryption", "none"), "flow": q.get("flow", "")}
            user = {k:v for k,v in user.items() if v != ""}
            return {"protocol":"vless", "settings":{"vnext":[{"address":host,"port":port,"users":[user]}]}, "streamSettings":stream}
        if proto == "trojan":
            if not host or not port: return None
            stream = _stream(q)
            if stream is None: return None
            pwd = unquote(u.username or "")
            if not pwd: return None
            return {"protocol":"trojan", "settings":{"servers":[{"address":host,"port":port,"password":pwd}]}, "streamSettings":stream}
        if proto == "vmess":
            obj = json.loads(_b64decode(cfg.split("://",1)[1].split("#",1)[0]).decode("utf-8", "ignore"))
            host = str(obj.get("add") or host); port = int(obj.get("port") or port)
            uid = str(obj.get("id") or obj.get("uuid") or "")
            if not host or not uid: return None
            stream = _stream({**q, **{k:str(v) for k,v in obj.items() if v is not None},
                              "type":obj.get("net", obj.get("type","tcp")),
                              "security":"tls" if obj.get("tls") else obj.get("security","")})
            if stream is None: return None
            user = {"id":uid,"alterId":int(obj.get("aid", obj.get("alterId",0)) or 0),
                    "security":str(obj.get("scy","auto"))}
            return {"protocol":"vmess", "settings":{"vnext":[{"address":host,"port":port,"users":[user]}]}, "streamSettings":stream}
        if proto == "ss":
            raw = cfg.split("://",1)[1].split("#",1)[0]
            if "@" not in raw:
                raw = _b64decode(raw).decode("utf-8", "ignore")
            else:
                raw = unquote(raw)
            userinfo, hp = raw.rsplit("@",1)
            if ":" not in userinfo:
                userinfo = _b64decode(userinfo).decode("utf-8", "ignore")
            method, password = userinfo.split(":",1)
            host2, port2 = hp.rsplit(":",1)
            return {"protocol":"shadowsocks", "settings":{"servers":[{"address":host2.strip("[]"),"port":int(port2),"method":method,"password":password}]}}
    except Exception:
        return None
    return None


def _free_port():
    s=socket.socket(); s.bind(("127.0.0.1",0)); p=s.getsockname()[1]; s.close(); return p

async def _probe_one(item):
    cfg=item.get("config","")
    xout=to_xray(cfg)
    if xout is None:
        item.update({"xray_tested":False,"xray_alive":False,"xray_error":"unsupported_or_invalid"})
        return item
    port=_free_port()
    doc={"log":{"loglevel":"error"},"inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"socks","settings":{"udp":False}}],
         "outbounds":[{**xout,"tag":"proxy"},{"protocol":"freedom","tag":"direct"}]}
    with tempfile.TemporaryDirectory(prefix="xfinder-xray-") as td:
        cf=Path(td)/"config.json"; cf.write_text(json.dumps(doc,separators=(",",":")),encoding="utf-8")
        try:
            proc=await asyncio.create_subprocess_exec(XRAY_BIN,"run","-c",str(cf),stdout=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.PIPE)
            await asyncio.sleep(0.35)
            start=time.perf_counter()
            curl=await asyncio.create_subprocess_exec("curl","--proxy",f"socks5h://127.0.0.1:{port}","--connect-timeout","4","--max-time",str(max(5,int(PROBE_TIMEOUT))),"-sS","-o","/dev/null","-w","%{http_code}",CANARY,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
            out,err=await asyncio.wait_for(curl.communicate(),timeout=PROBE_TIMEOUT+2)
            ms=round((time.perf_counter()-start)*1000,1)
            code=out.decode().strip()
            ok=code.isdigit() and 200 <= int(code) < 500
            if proc.returncode is None: proc.terminate()
            try: await asyncio.wait_for(proc.wait(),1.5)
            except Exception: proc.kill()
            item.update({"xray_tested":True,"xray_alive":ok,"xray_http_code":int(code) if code.isdigit() else None,
                         "http_ping_ms":ms if ok else None})
            if not ok: item["xray_error"]=(err.decode("utf-8","ignore")[-300:] or "canary_failed")
        except Exception as e:
            try:
                if proc.returncode is None: proc.kill()
            except Exception: pass
            item.update({"xray_tested":True,"xray_alive":False,"xray_error":str(e)[:300]})
    item["alive"]=bool(item.get("xray_alive"))
    return item

async def validate_xray(items):
    sem=asyncio.Semaphore(CONCURRENCY)
    async def one(x):
        async with sem: return await _probe_one(x)
    return await asyncio.gather(*(one(x) for x in items))
