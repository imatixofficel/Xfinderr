import json
from datetime import datetime, timezone
from .config import ROOT, OUTPUT_DIR, MAX_PUBLISH_BASE

def publish(items, remixed, wireguard=(), source_stats=(), raw_total=0, clean_ips=()):
    # فقط مواردی که واقعاً با Xray تأیید شده‌اند اجازه انتشار دارند.
    items=[x for x in items if x.get("xray_alive") is True and x.get("xray_tested") is True][:MAX_PUBLISH_BASE]
    remixed=[x for x in remixed if x.get("xray_alive") is True and x.get("xray_tested") is True]
    wireguard=[x for x in wireguard if x.get("verified") is True]
    all_items=list(remixed)+list(wireguard)+items
    for x in all_items:
        x["protocol"]=x.get("protocol") or x["config"].split("://",1)[0].lower()
        x.setdefault("http_ping_ms",None); x.setdefault("is_remixed",False)
        x.setdefault("country","UN"); x.setdefault("country_flag","🌐")
        x["verified"]=True
    OUTPUT_DIR.mkdir(exist_ok=True)
    groups={p:[] for p in ["vless","vmess","trojan","ss","hysteria2","wireguard"]}
    for x in all_items: groups.setdefault(x["protocol"],[]).append(x["config"])
    for p,lines in groups.items():
        (OUTPUT_DIR/f"{p}.txt").write_text("\n".join(lines)+("\n" if lines else ""),encoding="utf-8")
    (OUTPUT_DIR/"all.txt").write_text("\n".join(x["config"] for x in all_items)+("\n" if all_items else ""),encoding="utf-8")
    pings=[x.get("http_ping_ms") for x in all_items if x.get("http_ping_ms")]
    avg=round(sum(pings)/len(pings)) if pings else 0
    ok=[s for s in source_stats if s.get("ok")]
    data={"updated_at":datetime.now(timezone.utc).isoformat(),
          "stats":{"total":len(all_items),"raw_total":raw_total,"alive":len(items),"remixed":len(remixed),"wireguard":len(wireguard),"verified":len(all_items),"avg_ping":avg,"clean_ips":len(clean_ips)},
          "sources":{"total":len(source_stats),"active":len(ok),"dead_removed":len(source_stats)-len(ok)},
          "source_list":list(source_stats),"configs":all_items}
    (ROOT/"data/configs.json").write_text(json.dumps(data,ensure_ascii=False,separators=(",",":")),encoding="utf-8")
    (ROOT/"data/scan.json").write_text(json.dumps({"updated_at":data["updated_at"],"clean_ips":list(clean_ips)},ensure_ascii=False,separators=(",",":")),encoding="utf-8")
    return data
