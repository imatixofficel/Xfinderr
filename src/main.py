import asyncio
import json
from pathlib import Path

from .health_monitor import init_db
from .finder import collect, SOURCE_STATS
from .validator import validate, endpoint_info
from .xray_probe import validate_xray
from .ip_scanner import scan
from .remixer import build_with
from .publisher import publish
from .config import MAX_PUBLISH_BASE


def prepare_ports(items):
    """پورت‌های موردنیاز برای اسکن IPهای Clean را جمع می‌کند."""
    ports = {80, 443, 8080, 8443, 2053, 2083, 2087, 2096}
    for x in items:
        try:
            p = int(endpoint_info(x["config"])["port"])
            if 1 <= p <= 65535:
                ports.add(p)
        except Exception:
            pass
    return sorted(ports)[:32]


async def run():
    init_db()
    Path("data").mkdir(exist_ok=True)

    # ۱) جمع‌آوری کانفیگ‌های خام از منابع
    raw = await collect()
    raw = list({x["config"]: x for x in raw}.values())
    json.dump(
        raw,
        open("data/raw_configs.json", "w", encoding="utf-8"),
        ensure_ascii=False,
    )

    # ۲) تست transport/endpoint (TCP + TLS/HTTP در صورت وجود)
    transport_checked = await validate(raw)
    transport_alive = [x for x in transport_checked if x.get("alive")]

    # ۳) اعتبارسنجی کامل با Xray-core
    checked = await validate_xray(transport_alive)
    validated = [x for x in checked if x.get("xray_ok")]

    for x in validated:
        x["protocol"] = x["config"].split("://", 1)[0].lower()

    validated.sort(
        key=lambda x: (
            x.get("tcp_ping_ms") or 999999,
            x.get("http_ping_ms") or 999999,
        )
    )
    json.dump(
        validated,
        open("data/validated.json", "w", encoding="utf-8"),
        ensure_ascii=False,
    )

    # ۴) اسکن IPهای Clean (فقط از منبع تعریف‌شده)
    ports = prepare_ports(validated)
    clean = await scan(ports)
    json.dump(
        clean,
        open("data/scanned_clean_ips.json", "w", encoding="utf-8"),
        ensure_ascii=False,
    )

    # ۵) ساخت Remix + تست دوباره‌ی هر Remix
    _, remixed_candidates = build_with(validated, clean)
    remixed_transport = await validate(remixed_candidates)
    remixed_transport = [x for x in remixed_transport if x.get("alive")]

    remixed_checked = await validate_xray(remixed_transport)
    remixed = [x for x in remixed_checked if x.get("xray_ok")]

    for x in remixed:
        x["protocol"] = x["config"].split("://", 1)[0].lower()
        x["is_remixed"] = True

    remixed.sort(
        key=lambda x: (
            x.get("tcp_ping_ms") or 999999,
            x.get("http_ping_ms") or 999999,
        )
    )
    json.dump(
        remixed,
        open("data/remixed.json", "w", encoding="utf-8"),
        ensure_ascii=False,
    )

    # ۶) انتشار خروجی‌ها (بدون WARP/WireGuard با کلید خصوصی)
    publish(
        validated[:MAX_PUBLISH_BASE],
        remixed,
        [],
        list(SOURCE_STATS),
        len(raw),
        len(clean),
    )

    print(
        f"Xfinder complete: collected={len(raw)} "
        f"transport_alive={len(transport_alive)} "
        f"xray_alive={len(validated)} "
        f"scanned_ips={len(clean)} "
        f"remixed_xray_alive={len(remixed)}"
    )


if __name__ == "__main__":
    asyncio.run(run())
