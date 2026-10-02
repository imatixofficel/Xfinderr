"""ساخت خودکار کانفیگ WireGuard (Cloudflare WARP) با IPهای تمیز.
فقط کتابخانه استاندارد پایتون؛ کلید X25519 به‌صورت خالص پایتون تولید می‌شود."""
import base64, json, os
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.parse import quote
from .config import WG_ACCOUNTS, WG_ENDPOINTS_PER_ACCOUNT, WG_PORT, WARP_ACCOUNTS_FILE

_P = 2**255 - 19
_A24 = 121665

def _x25519(k: bytes, u: bytes) -> bytes:
    k = bytearray(k); k[0] &= 248; k[31] &= 127; k[31] |= 64
    kn = int.from_bytes(k, "little")
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in range(254, -1, -1):
        bit = (kn >> t) & 1
        swap ^= bit
        if swap: x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a = (x2 + z2) % _P; aa = a * a % _P
        b = (x2 - z2) % _P; bb = b * b % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P; d = (x3 - z3) % _P
        da = d * a % _P; cb = c * b % _P
        x3 = pow(da + cb, 2, _P); z3 = x1 * pow(da - cb, 2, _P) % _P
        x2 = aa * bb % _P; z2 = e * (aa + _A24 * e) % _P
    if swap: x2, x3, z2, z3 = x3, x2, z3, z2
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, "little")

def keypair():
    priv = os.urandom(32)
    pub = _x25519(priv, (9).to_bytes(32, "little"))
    return base64.b64encode(priv).decode(), base64.b64encode(pub).decode()

def register_warp():
    priv, pub = keypair()
    body = json.dumps({"key": pub, "install_id": "", "fcm_token": "", "type": "Android", "locale": "en_US",
                       "tos": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")}).encode()
    req = Request("https://api.cloudflareclient.com/v0a2158/reg", data=body, method="POST",
                  headers={"Content-Type": "application/json", "User-Agent": "okhttp/3.12.1", "CF-Client-Version": "a-6.3-1922"})
    d = json.loads(urlopen(req, timeout=20).read().decode())
    c = d["config"]
    return {"private_key": priv, "peer_public_key": c["peers"][0]["public_key"],
            "v4": c["interface"]["addresses"]["v4"], "v6": c["interface"]["addresses"]["v6"]}

def load_accounts():
    accounts = []
    try: accounts = json.loads(WARP_ACCOUNTS_FILE.read_text(encoding="utf-8"))
    except Exception: pass
    changed = False
    while len(accounts) < WG_ACCOUNTS:
        try: accounts.append(register_warp()); changed = True
        except Exception as e:
            print("warp register failed:", e); break
    if changed:
        WARP_ACCOUNTS_FILE.parent.mkdir(exist_ok=True)
        WARP_ACCOUNTS_FILE.write_text(json.dumps(accounts, indent=1), encoding="utf-8")
    return accounts

def conf_text(acc, host, port):
    return (f"[Interface]\nPrivateKey = {acc['private_key']}\nAddress = {acc['v4']}/32, {acc['v6']}/128\n"
            f"DNS = 1.1.1.1, 1.0.0.1\nMTU = 1280\n\n[Peer]\nPublicKey = {acc['peer_public_key']}\n"
            f"AllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = {host}:{port}\nPersistentKeepalive = 25\n")

def uri(acc, host, port, name):
    return (f"wireguard://{quote(acc['private_key'], safe='')}@{host}:{port}?address={quote(acc['v4']+'/32,'+acc['v6']+'/128', safe='')}"
            f"&publickey={quote(acc['peer_public_key'], safe='')}&mtu=1280#{quote(name)}")

def build(clean_ips):
    """clean_ips: [{'ip','ping'}] -> آیتم‌های هم‌شکل با بقیه کانفیگ‌ها."""
    if not clean_ips: return []
    accounts = load_accounts()
    out, n = [], 0
    for ai, acc in enumerate(accounts):
        for ip in clean_ips[ai * WG_ENDPOINTS_PER_ACCOUNT:(ai + 1) * WG_ENDPOINTS_PER_ACCOUNT]:
            host = ip["ip"]; n += 1; name = f"Xfinder-WG-{n}"
            out.append({"config": uri(acc, host, WG_PORT, name), "conf": conf_text(acc, host, WG_PORT),
                        "protocol": "wireguard", "source": "Cloudflare WARP + CleanIP", "trust_score": 95,
                        "server": host, "port": WG_PORT, "tcp_ping_ms": ip.get("ping") or None,
                        "alive": True, "is_remixed": True, "http_ping_ms": None})
    return out
