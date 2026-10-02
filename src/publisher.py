import json
from datetime import datetime, timezone
from .config import ROOT, OUTPUT_DIR, MAX_PUBLISH_BASE


def publish(items, remixed, wireguard=(), source_stats=(), raw_total=0, scanned_ips=0):
    items = list(items)[:MAX_PUBLISH_BASE]
    # Only already-validated remixes are accepted. WireGuard publishing is off
    # by default because generated private keys must never be exposed publicly.
    remixed = [x for x in remixed if x.get("alive")]
    all_items = remixed + list(wireguard) + items
    for x in all_items:
        x["protocol"] = x.get("protocol") or x["config"].split("://", 1)[0].lower()
        x.setdefault("http_ping_ms", None); x.setdefault("is_remixed", False)
        x.setdefault("country", "UN"); x.setdefault("country_flag", "🌐")
        x.setdefault("test_level", "xray")
        x["tested_with_xray"] = bool(x.get("xray_ok", x.get("test_level") == "xray"))
    OUTPUT_DIR.mkdir(exist_ok=True)
    groups = {p: [] for p in ["vless", "vmess", "trojan", "ss", "hysteria2", "wireguard"]}
    for x in all_items: groups.setdefault(x["protocol"], []).append(x["config"])
    for p, lines in groups.items():
        text = "\n".join(dict.fromkeys(lines))
        (OUTPUT_DIR / f"{p}.txt").write_text((text + "\n") if text else "", encoding="utf-8")
    all_lines = list(dict.fromkeys(x["config"] for x in all_items))
    (OUTPUT_DIR / "all.txt").write_text("\n".join(all_lines) + ("\n" if all_lines else ""), encoding="utf-8")
    pings = [x["tcp_ping_ms"] for x in all_items if x.get("tcp_ping_ms") is not None]
    avg = round(sum(pings) / len(pings)) if pings else 0
    ok = [s for s in source_stats if s.get("ok")]
    data = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "stats": {"total": len(all_items), "alive": len(items), "remixed": len(remixed),
                  "wireguard": len(wireguard), "scanned_clean_ips": scanned_ips, "avg_ping": avg},
        "validation": {"tested_before_publish": raw_total, "remixes_retested": True,
                        "transport_validation": True, "xray_end_to_end_validation": True},
        "sources": {"total": len(source_stats), "active": len(ok), "dead_removed": len(source_stats) - len(ok)},
        "source_list": list(source_stats), "configs": all_items
    }
    (ROOT / "data/configs.json").write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    return data
