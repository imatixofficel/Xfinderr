"""ساخت نسخه‌های Remix با IPهای تمیز؛ پارامترهای TLS/SNI/Host حفظ می‌شوند."""
import base64,json,re
from urllib.request import Request,urlopen
from .config import MAX_REMIX_PING,REMIX_PER_CONFIG,REMIX_BASE_LIMIT
from .ip_scanner import fetch_candidates, scan

def fetch_clean():
    """Fetch the supplied Clean-IP list and return it unchanged for compatibility.
    Actual reachability is performed by scan_clean below.
    """
    try:
        rows=fetch_candidates()
        return rows
    except Exception as e:
        print("clean ip source failed:",e); return []

async def scan_clean(ips, ports):
    return await scan(ips, ports)

def remix_config(cfg,new_ip):
    proto=cfg.split("://",1)[0].lower()
    if proto=="vmess":
        try:
            raw=cfg.split("://",1)[1].split("#",1)[0];raw += "="*((4-len(raw)%4)%4)
            obj=json.loads(base64.b64decode(raw).decode("utf-8","ignore"));old=obj.get("add","");obj["add"]=new_ip
            if not obj.get("sni") and obj.get("tls"):obj["sni"]=obj.get("host") or old
            if not obj.get("host"):obj["host"]=old
            label=cfg.split("#",1)[1] if "#" in cfg else "Xfinder-remix"
            body=base64.b64encode(json.dumps(obj,separators=(",",":"),ensure_ascii=False).encode()).decode().rstrip("=")
            return "vmess://"+body+"#"+label
        except Exception:pass
    m=re.search(r"@(\[[^\]]+\]|[^:/?#]+)",cfg)
    if not m:return cfg
    old=m.group(1).strip("[]")
    out=cfg[:m.start(1)]+new_ip+cfg[m.end(1):]
    head,_,tag=out.partition("#")
    if "?" in head:
        if "sni=" not in head and "security=none" not in head:head+="&sni="+old
        if "host=" not in head and "type=ws" in head:head+="&host="+old
    return head+("#"+tag if tag else "")

def build(items):
    return build_with(items, fetch_clean())

def build_with(items, ips):
    if not ips: return items, []
    remixed=[]
    base=sorted(items,key=lambda x:(-int(x.get("trust_score",0)),x.get("http_ping_ms") or x.get("tcp_ping_ms") or 9999))[:REMIX_BASE_LIMIT]
    for item in base:
        if item.get("protocol") not in {"vless","vmess","trojan"}: continue
        port=int(item.get("port") or 443)
        eligible=[ip for ip in ips if int(ip.get("port") or 0)==port]
        for clean in eligible[:REMIX_PER_CONFIG]:
            r=dict(item); r["config"]=remix_config(item["config"],clean["ip"]); r["server"]=clean["ip"]
            r["is_remixed"]=True; r["remix_ping_ms"]=clean.get("ping"); r["source"]=item.get("source","")+" + CleanIP"
            r["alive"]=False; r["xray_tested"]=False; remixed.append(r)
    return items,remixed

if __name__=="__main__":
    import json
    data=json.load(open("data/validated.json",encoding="utf-8")); ips=fetch_clean()
    _,r=build_with(data,ips)
    json.dump(r,open("data/remixed.json","w",encoding="utf-8"),ensure_ascii=False,indent=2)
    print("remixed candidates:",len(r))
