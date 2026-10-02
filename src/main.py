import asyncio, json
from pathlib import Path
from .health_monitor import init_db
from .finder import collect, SOURCE_STATS
from .validator import validate, endpoint_info
from .xray_probe import validate_xray
from .ip_scanner import run_sync
from .remixer import build_with
from .publisher import publish
from .config import MAX_PUBLISH_BASE


def prepare_ports(items):
    ports = {80, 443, 8080, 8443, 2053, 2083, 2087, 2096}
    for x in items:
        try:
            p = int(endpoint_info(x["config"])["port"])
            if 1 <= p <= 65535: ports.add(p)
        except Exception:
            pass
    return sorted(ports)[:32]


async def run():
    init_db()
    Path("data").mkdir(exist_ok=True)

    raw = await collect()
    raw = list({x["config"]: x for x in raw}.values())
    json.dump(raw, open("data/raw_configs.json", "w", encoding="utf-8"), ensure_ascii=False)

    # Every source config is tested. TCP + TLS/HTTP transport checks are used
    # where applicable; failed candidates never reach publication.
    transport_checked = await validate(raw)
    transport_alive = [x for x in transport_checked if x.get("alive")]
    # Full end-to-end validation through Xray-core. Only these candidates may publish.
    checked = await validate_xray(transport_alive)
    validated = [x for x in checked if x.get("xray_ok")]
    for x in validated:
        x["protocol"] = x["config"].split("://", 1)[0].lower()
    validated.sort(key=lambda x: (x.get("tcp_ping_ms") or 999999, x.get("http_ping_ms") or 999999))
    json.dump(validated, open("data/validated.json", "w", encoding="utf-8"), ensure_ascii=False)

    # Scan only IPs supplied by the configured clean-IP source.  No arbitrary
    # CIDR/range is accepted by the scanner.
    ports = prepare_ports(validated)
    clean = run_sync(ports)
    json.dump(clean, open("data/scanned_clean_ips.json", "w", encoding="utf-8"), ensure_ascii=False)

    # Combine configs with scanned IPs, then TEST THE REMIXED CONFIG AGAIN.
    _, remixed_candidates = build_with(validated, clean)
    remixed_transport = await validate(remixed_candidates)
    remixed_transport = [x for x in remixed_transport if x.get("alive")]
    remixed_checked = await validate_xray(remixed_transport)
    remixed = [x for x in remixed_checked if x.get("xray_ok")]
    for x in remixed:
        x["protocol"] = x["config"].split("://", 1)[0].lower()
        x["is_remixed"] = True
    remixed.sort(key=lambda x: (x.get("tcp_ping_ms") or 999999, x.get("http_ping_ms") or 999999))
    json.dump(remixed, open("data/remixed.json", "w", encoding="utf-8"), ensure_ascii=False)

    # Server-side WARP private keys are intentionally NOT generated/published.
    # A public repository must not commit private WireGuard keys.
    publish(validated[:MAX_PUBLISH_BASE], remixed, [], list(SOURCE_STATS), len(raw), len(clean))
    print(f"Xfinder complete: collected={len(raw)} transport_alive={len(transport_alive)} xray_alive={len(validated)} scanned_ips={len(clean)} remixed_xray_alive={len(remixed)}")


if __name__ == "__main__":
    asyncio.run(run())
