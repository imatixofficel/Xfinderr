"""جمع‌آوری کانفیگ‌ها از منابع تعریف‌شده و نرمال‌سازی فرمت‌های مختلف."""
import asyncio, base64, json, re
from urllib.request import Request, urlopen
from .config import SOURCES, BLACKLIST

URI_PATTERN=re.compile(r"(?i)(?:vless|vmess|trojan|ss|hysteria2)://[^\s\"'<>\\]+")

def fetch(url, timeout=20):
    req=Request(url,headers={"User-Agent":"Xfinder/1.1 (+GitHub Actions)"})
    with urlopen(req,timeout=timeout) as r:
        return r.read().decode("utf-8","ignore")

def decode_base64_text(text):
    compact="".join(text.split())
    if len(compact)<16:return ""
    try:
        return base64.b64decode(compact+"===",validate=False).decode("utf-8","ignore")
    except Exception:
        return ""

def vmess_json_to_uri(obj):
    """VMess JSON قدیمی را به vmess:// base64 تبدیل می‌کند."""
    if not isinstance(obj,dict) or not obj.get("add") or not obj.get("port"):
        return None
    clean={
      "v":str(obj.get("v",2)),"ps":str(obj.get("ps",obj.get("remarks","Xfinder"))),
      "add":str(obj["add"]),"port":str(obj["port"]),"id":str(obj.get("id",obj.get("uuid",""))),
      "aid":str(obj.get("aid",obj.get("alterId",0))),"scy":str(obj.get("scy","auto")),
      "net":str(obj.get("net",obj.get("type","tcp"))),"type":str(obj.get("type","none")),
      "host":str(obj.get("host",obj.get("headers",{}).get("Host","") if isinstance(obj.get("headers"),dict) else "")),
      "path":str(obj.get("path","")),"tls":str(obj.get("tls","")),"sni":str(obj.get("sni","")),
      "alpn":str(obj.get("alpn","")),"fp":str(obj.get("fp","")),"allowInsecure":str(obj.get("allowInsecure",obj.get("allow_insecure","")))
    }
    raw=json.dumps(clean,separators=(",",":"),ensure_ascii=False).encode()
    return "vmess://"+base64.b64encode(raw).decode().rstrip("=")

def extract(text):
    """URI مستقیم، Base64 subscription و JSONهای Delta را پشتیبانی می‌کند."""
    bodies=[text]
    decoded=decode_base64_text(text)
    if decoded:bodies.append(decoded)
    found=[]
    for body in bodies:
        found.extend(URI_PATTERN.findall(body))
        # JSONهای حاوی add/port را هم بررسی کن.
        try:
            parsed=json.loads(body)
            stack=[parsed]
            while stack:
                x=stack.pop()
                if isinstance(x,dict):
                    u=vmess_json_to_uri(x)
                    if u:found.append(u)
                    stack.extend(x.values())
                elif isinstance(x,list):stack.extend(x)
        except Exception:pass
    cleaned=[]
    for u in found:
        u = u.rstrip(".,;)]}")
        # Drop obviously truncated query/JSON fragments instead of publishing
        # malformed share links such as `extra={`.
        if u.count("{") != u.count("}") or u.count("[") != u.count("]"):
            continue
        if "://" not in u or len(u.split("://", 1)[1]) < 8:
            continue
        if u not in cleaned: cleaned.append(u)
    return cleaned

SOURCE_STATS=[]

async def collect():
    loop=asyncio.get_running_loop();out=[];SOURCE_STATS.clear()
    async def one(src):
        if any(b.lower() in src["name"].lower() for b in BLACKLIST):return []
        try:
            text=await loop.run_in_executor(None,fetch,src["url"])
            items=[{"config":cfg,"source":src["name"],"trust_score":src["trust"]} for cfg in extract(text)]
            SOURCE_STATS.append({"name":src["name"],"trust":src["trust"],"count":len(items),"ok":bool(items)})
            return items
        except Exception as e:
            print("source failed:",src["name"],e)
            SOURCE_STATS.append({"name":src["name"],"trust":src["trust"],"count":0,"ok":False});return []
    batches=await asyncio.gather(*(one(s) for s in SOURCES))
    for batch in batches:out.extend(batch)
    return out

if __name__=="__main__":
    data=asyncio.run(collect())
    json.dump(data,open("data/raw_configs.json","w",encoding="utf-8"),ensure_ascii=False,indent=2)
    print("collected",len(data))
