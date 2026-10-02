"""Network-level validation for Xfinder configs.

Every candidate is checked against its actual endpoint.  TLS endpoints get a
TLS handshake using the original SNI when available; WebSocket/HTTP transports
also receive a lightweight HTTP probe.  This is intentionally a transport
validator (not a full Xray protocol implementation).
"""
import asyncio, base64, hashlib, json, re, socket, ssl, time
from urllib.parse import urlparse, parse_qs, unquote
from .config import CONCURRENCY, TCP_TIMEOUT, HTTP_TIMEOUT


def vmess_obj(cfg):
    try:
        raw = cfg.split("://", 1)[1].split("#", 1)[0]
        raw += "=" * ((4 - len(raw) % 4) % 4)
        return json.loads(base64.b64decode(raw).decode("utf-8", "ignore"))
    except Exception:
        return {}


def endpoint_info(cfg):
    proto = cfg.split("://", 1)[0].lower()
    if proto == "vmess":
        o = vmess_obj(cfg)
        host = str(o.get("add", ""))
        try: port = int(o.get("port", 443))
        except Exception: port = 443
        tls = str(o.get("tls", "")).lower() in {"tls", "https", "reality"} or bool(o.get("sni"))
        sni = str(o.get("sni") or o.get("host") or host)
        net = str(o.get("net") or o.get("type") or "tcp").lower()
        path = str(o.get("path") or "/")
        return {"host": host, "port": port, "tls": tls, "sni": sni, "network": net, "path": path}
    try:
        u = urlparse(cfg)
        q = parse_qs(u.query)
        host = u.hostname or ""
        port = u.port or 443
        security = (q.get("security", [""])[0] or q.get("tls", [""])[0]).lower()
        tls = security in {"tls", "reality", "https"} or proto in {"trojan"}
        sni = q.get("sni", [""])[0] or q.get("host", [""])[0] or host
        network = q.get("type", [q.get("network", ["tcp"])[0]])[0].lower()
        path = unquote(q.get("path", ["/"])[0] or "/")
        return {"host": host, "port": port, "tls": tls, "sni": sni, "network": network, "path": path}
    except Exception:
        return {"host": "", "port": 443, "tls": False, "sni": "", "network": "tcp", "path": "/"}


def endpoint(cfg):
    i = endpoint_info(cfg)
    return i["host"], i["port"]


def _tls_context():
    return ssl.create_default_context()


async def tcp_connect(host, port, timeout=TCP_TIMEOUT, ssl_name=None):
    start = time.perf_counter()
    writer = None
    try:
        if ssl_name:
            ctx = _tls_context()
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ctx, server_hostname=ssl_name), timeout=timeout
                )
                verified = True
            except (ssl.SSLError, ValueError):
                # Some public endpoints deliberately use a certificate that does
                # not match the transport IP.  Retry without certificate
                # verification, but record that fact for the published metadata.
                if writer:
                    writer.close()
                    try: await writer.wait_closed()
                    except Exception: pass
                insecure = ssl._create_unverified_context()
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=insecure, server_hostname=ssl_name), timeout=timeout
                )
                verified = False
        else:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            verified = None
        ms = round((time.perf_counter() - start) * 1000, 1)
        writer.close()
        try: await writer.wait_closed()
        except Exception: pass
        return True, ms, None, verified
    except Exception as e:
        try:
            if writer:
                writer.close()
                await writer.wait_closed()
        except Exception: pass
        return False, None, type(e).__name__, None


async def http_probe(host, port, tls, sni, path, timeout=HTTP_TIMEOUT):
    """Lightweight HTTP/WS transport probe.  A 101/2xx/3xx is considered a
    transport response; 4xx still proves the HTTP server is reachable."""
    start = time.perf_counter()
    writer = None
    try:
        ctx = _tls_context() if tls else None
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=(sni or host) if tls else None),
            timeout=timeout,
        )
        nonce = base64.b64encode(hashlib.sha1(f"{time.time_ns()}".encode()).digest()[:16]).decode()
        p = path if path.startswith("/") else "/" + path
        host_header = sni or host
        req = (
            f"GET {p} HTTP/1.1\r\nHost: {host_header}\r\n"
            "User-Agent: Xfinder/2.2\r\nConnection: Upgrade\r\n"
            "Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Key: {nonce}\r\n\r\n"
        ).encode()
        writer.write(req); await writer.drain()
        head = await asyncio.wait_for(reader.read(512), timeout=timeout)
        status = re.search(rb"HTTP/\d(?:\.\d)?\s+(\d{3})", head)
        code = int(status.group(1)) if status else None
        ok = code is not None and (100 <= code < 500)
        return ok, round((time.perf_counter() - start) * 1000, 1), code
    except Exception as e:
        return False, None, type(e).__name__
    finally:
        if writer:
            writer.close()
            try: await writer.wait_closed()
            except Exception: pass


async def probe(item, sem):
    async with sem:
        cfg = item.get("config", "")
        info = endpoint_info(cfg)
        host, port = info["host"], info["port"]
        item.update({"server": host, "port": port, "alive": False, "test_level": "failed",
                     "tcp_ping_ms": None, "http_ping_ms": None, "http_status": None,
                     "test_error": None})
        if not host or not (1 <= port <= 65535):
            item["test_error"] = "invalid_endpoint"; return item
        tls = info["tls"]
        ok, ms, err, tls_verified = await tcp_connect(host, port, ssl_name=(info["sni"] if tls else None))
        item["tcp_ping_ms"] = ms
        item["tls_verified"] = tls_verified
        if not ok:
            item["test_error"] = err; return item
        item["alive"] = True
        item["test_level"] = "tcp" if not tls else "tls"
        # HTTP-like transports get a second transport-level check.
        if info["network"] in {"ws", "websocket", "http", "h2", "httpupgrade"}:
            hok, hms, status = await http_probe(host, port, tls, info["sni"], info["path"])
            item["http_ping_ms"] = hms; item["http_status"] = status
            if hok:
                item["test_level"] = "http"
            elif info["network"] in {"ws", "websocket"}:
                item["alive"] = False
                item["test_level"] = "failed"
                item["test_error"] = "http_transport_probe_failed"
        return item


async def validate(items):
    sem = asyncio.Semaphore(CONCURRENCY)
    return await asyncio.gather(*(probe(dict(x), sem) for x in items))


if __name__ == "__main__":
    raw = json.load(open("data/raw_configs.json", encoding="utf-8"))
    good = [x for x in asyncio.run(validate(raw)) if x["alive"]]
    json.dump(good, open("data/validated.json", "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("validated:", len(good))
