import asyncio, json
from pathlib import Path
from .health_monitor import init_db
from .finder import collect, SOURCE_STATS
from .validator import validate
from .remixer import build_with
from .ip_scanner import fetch_candidates, scan
from .publisher import publish
from .validator import endpoint
from .config import IP_SCAN_PORT_LIMIT

async def run():
    init_db(); Path("data").mkdir(exist_ok=True); Path("output").mkdir(exist_ok=True)
    raw = await collect()
    # مرحله ۱: هر کانفیگ ابتدا TCP و سپس با Xray از طریق HTTPS واقعی تست می‌شود.
    validated = await validate(raw, xray=True)
    for x in validated:
        x["protocol"] = x["config"].split("://", 1)[0].lower()
    validated.sort(key=lambda x: x.get("http_ping_ms") or x.get("tcp_ping_ms") or 999999)

    # مرحله ۲: فقط IPهایی که منبع Clean-IP ارائه کرده را اسکن می‌کنیم.
    # هیچ CIDR یا رنج تصادفی اسکن نمی‌شود.
    try:
        candidates = fetch_candidates()
        ports=[]
        for x in validated:
            try: ports.append(endpoint(x["config"])[1])
            except Exception: pass
        ports = sorted(set([p for p in ports if 1 <= p <= 65535]))[:IP_SCAN_PORT_LIMIT]
        if not ports: ports=[443,80]
        clean = await scan(candidates, ports)
    except Exception as e:
        print("clean IP scan failed:",e); clean=[]

    # مرحله ۳: ترکیب IP سالم با کانفیگ و تست مجدد خود Remix با Xray.
    _, remixed_candidates = build_with(validated, clean)
    remixed = [x for x in await validate(remixed_candidates, xray=True)]
    for x in remixed:
        x["protocol"] = x["config"].split("://", 1)[0].lower(); x["is_remixed"] = True
    remixed.sort(key=lambda x: x.get("http_ping_ms") or x.get("tcp_ping_ms") or 999999)

    # WireGuard خودکار در این نسخه منتشر نمی‌شود چون runner بدون فعال‌سازی تونل
    # نمی‌تواند آن را end-to-end تست کند. سازنده WARP داخل سایت مستقل باقی می‌ماند.
    wg=[]
    publish(validated, remixed, wg, list(SOURCE_STATS), len(raw), clean_ips=clean)
    print(f"Xfinder complete: {len(validated)} verified, {len(remixed)} verified remixed, {len(clean)} clean IPs")

if __name__ == "__main__": asyncio.run(run())
