"""Two-stage validation: TCP reachability, then real protocol validation via Xray."""
import asyncio, base64, json, re, socket, time
from urllib.parse import urlparse
from .config import CONCURRENCY, TCP_TIMEOUT, XRAY_CANDIDATE_LIMIT
from .xray_probe import validate_xray

def vmess_endpoint(cfg):
    try:
        raw=cfg.split("://",1)[1].split("#",1)[0]
        raw += "="*((4-len(raw)%4)%4)
        obj=json.loads(base64.b64decode(raw).decode("utf-8","ignore"))
        return str(obj.get("add", "")), int(obj.get("port",443))
    except Exception:return "",443

def endpoint(cfg):
    proto=cfg.split("://",1)[0].lower()
    if proto=="vmess": return vmess_endpoint(cfg)
    try:
        u=urlparse(cfg); host=u.hostname or ""; port=u.port or 443
        if host:return host,port
    except Exception:pass
    m=re.search(r"@([^/?#]+)",cfg)
    if m:
        hp=m.group(1)
        try:
            host,port=hp.rsplit(":",1);return host.strip("[]"),int(port)
        except Exception:return hp.strip("[]"),443
    return "",443

async def tcp_probe(item,sem):
    async with sem:
        host,port=endpoint(item["config"]); start=time.perf_counter()
        if not host:
            item.update({"server":"","port":port,"tcp_ping_ms":None,"tcp_alive":False}); return item
        try:
            reader,writer=await asyncio.wait_for(asyncio.open_connection(host,port,family=socket.AF_UNSPEC),timeout=TCP_TIMEOUT)
            ms=round((time.perf_counter()-start)*1000,1); writer.close()
            try: await writer.wait_closed()
            except Exception: pass
            item.update({"server":host,"port":port,"tcp_ping_ms":ms,"tcp_alive":True})
        except Exception:
            item.update({"server":host,"port":port,"tcp_ping_ms":None,"tcp_alive":False})
        return item

async def validate(items, xray=True):
    sem=asyncio.Semaphore(CONCURRENCY)
    tcp=await asyncio.gather(*(tcp_probe(x,sem) for x in items))
    candidates=[x for x in tcp if x.get("tcp_alive")]
    candidates.sort(key=lambda x:(-float(x.get("trust_score",0)),x.get("tcp_ping_ms") or 999999))
    candidates=candidates[:XRAY_CANDIDATE_LIMIT]
    if not xray:
        for x in candidates: x["xray_tested"]=False; x["alive"]=True
        return candidates
    checked=await validate_xray(candidates)
    return [x for x in checked if x.get("xray_alive")]

if __name__=="__main__":
    raw=json.load(open("data/raw_configs.json",encoding="utf-8"))
    good=asyncio.run(validate(raw))
    json.dump(good,open("data/validated.json","w",encoding="utf-8"),ensure_ascii=False,indent=2)
    print("verified:",len(good))
