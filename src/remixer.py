"""Combine validated configs with IPs/ports that were actually observed open."""
import base64, json
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit
from .config import REMIX_BASE_LIMIT, REMIX_PER_CONFIG


def remix_config(cfg, new_ip, new_port=None):
    proto = cfg.split("://", 1)[0].lower()
    if proto == "vmess":
        try:
            raw = cfg.split("://", 1)[1].split("#", 1)[0]
            raw += "=" * ((4-len(raw)%4)%4)
            obj = json.loads(base64.b64decode(raw).decode("utf-8", "ignore"))
            old = obj.get("add", "")
            old_port = obj.get("port", 443)
            obj["add"] = new_ip
            if new_port: obj["port"] = str(new_port)
            if not obj.get("sni") and obj.get("tls"): obj["sni"] = obj.get("host") or old
            if not obj.get("host"): obj["host"] = old
            label = cfg.split("#", 1)[1] if "#" in cfg else "Xfinder-remix"
            body = base64.b64encode(json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode()).decode().rstrip("=")
            return "vmess://" + body + "#" + label
        except Exception:
            return cfg
    try:
        parts = urlsplit(cfg)
        if not parts.hostname: return cfg
        netloc = parts.netloc.replace(parts.hostname, new_ip, 1)
        if new_port:
            userinfo = ""
            if "@" in netloc: userinfo, _ = netloc.rsplit("@", 1); userinfo += "@"
            netloc = userinfo + new_ip + ":" + str(new_port)
        q = parse_qs(parts.query, keep_blank_values=True)
        old = parts.hostname
        if proto in {"vless", "trojan"}:
            if q.get("security", [""])[0] in {"tls", "reality"} and not q.get("sni"): q["sni"] = [old]
            if q.get("type", [""])[0] in {"ws", "websocket"} and not q.get("host"): q["host"] = [old]
        return urlunsplit((parts.scheme, netloc, parts.path, urlencode(q, doseq=True), parts.fragment))
    except Exception:
        return cfg


def build_with(items, ips):
    if not ips: return items, []
    base = sorted(items, key=lambda x: (-(int(x.get("trust_score") or 0)), x.get("tcp_ping_ms") or 999999))[:REMIX_BASE_LIMIT]
    by_port = {}
    for ip in ips:
        by_port.setdefault(int(ip.get("port") or 0), []).append(ip)
    remixed = []
    for item in base:
        if item.get("protocol") not in {"vless", "vmess", "trojan"}: continue
        try: port = int(item.get("port") or 443)
        except Exception: port = 443
        candidates = by_port.get(port, [])[:REMIX_PER_CONFIG]
        for clean in candidates:
            r = dict(item)
            r["config"] = remix_config(item["config"], clean["ip"], port)
            r["server"] = clean["ip"]; r["port"] = port; r["is_remixed"] = True
            r["source"] = item.get("source", "") + " + ScannedCleanIP"
            r["remix_ping_ms"] = clean.get("ping")
            r["clean_ip_source_port"] = clean.get("port")
            remixed.append(r)
    return items, remixed
