"""Validate the supplied clean-IP list against ports actually used by live configs.
No CIDR discovery is performed; only IPs from CLEAN_IPS_URL are tested."""
from __future__ import annotations
import asyncio, json, socket, time
from urllib.request import Request, urlopen
from .config import CLEAN_IPS_URL, IP_SCAN_CONCURRENCY, IP_SCAN_TIMEOUT, IP_SCAN_LIMIT, IP_SCAN_PORT_LIMIT

def fetch_candidates():
    req=Request(CLEAN_IPS_URL,headers={"User-Agent":"Xfinder/2.2"})
    raw=urlopen(req,timeout=15).read().decode("utf-8","ignore")
    data=json.loads(raw)
    if isinstance(data,dict): data=data.get("ips") or data.get("data") or data.get("results") or []
    out=[]; seen=set()
    for x in data or []:
        ip=x if isinstance(x,str) else (x.get("ip") or x.get("address"))
        if ip and ip not in seen:
            seen.add(ip); out.append({"ip":ip})
        if len(out)>=IP_SCAN_LIMIT: break
    return out

async def _probe(ip,port,sem):
    async with sem:
        t=time.perf_counter()
        try:
            r,w=await asyncio.wait_for(asyncio.open_connection(ip,port,family=socket.AF_UNSPEC),IP_SCAN_TIMEOUT)
            ms=round((time.perf_counter()-t)*1000,1); w.close()
            try: await w.wait_closed()
            except Exception: pass
            return {"ip":ip,"port":port,"ping":ms}
        except Exception: return None

async def scan(ips,ports):
    sem=asyncio.Semaphore(IP_SCAN_CONCURRENCY)
    tasks=[_probe(x["ip"],p,sem) for x in ips for p in ports[:IP_SCAN_PORT_LIMIT]]
    rows=await asyncio.gather(*tasks)
    good=[x for x in rows if x]
    best={}
    for x in good:
        old=best.get(x["ip"])
        if old is None or x["ping"]<old["ping"]: best[x["ip"]]=x
    return sorted(best.values(),key=lambda x:x["ping"])
