"""Bounded clean-IP validator.

Only IPs obtained from the configured clean-IP source are checked. The scanner
never accepts arbitrary CIDRs and caps the number of IP/port probes per run.
"""
import asyncio
import ipaddress
import json
import time
from urllib.request import Request, urlopen

from .config import (
    CLEAN_IPS_URL,
    MAX_IPS_TO_SCAN,
    IP_SCAN_CONCURRENCY,
    IP_SCAN_TIMEOUT,
)


def load_candidates():
    req = Request(CLEAN_IPS_URL, headers={"User-Agent": "Xfinder/2.2"})
    raw = urlopen(req, timeout=20).read().decode("utf-8", "ignore")
    data = json.loads(raw)

    if isinstance(data, dict):
        data = data.get("ips") or data.get("data") or data.get("results") or []

    out = []
    for x in data:
        ip = (
            x
            if isinstance(x, str)
            else (x.get("ip") or x.get("address")) if isinstance(x, dict) else None
        )
        if not ip:
            continue
        try:
            ipaddress.ip_address(ip.strip())
            out.append(ip.strip())
        except ValueError:
            continue
    return list(dict.fromkeys(out))[:MAX_IPS_TO_SCAN]


async def check(ip, port, sem):
    async with sem:
        start = time.perf_counter()
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=IP_SCAN_TIMEOUT
            )
            ms = round((time.perf_counter() - start) * 1000, 1)
            w.close()
            try:
                await w.wait_closed()
            except Exception:
                pass
            return {"ip": ip, "port": port, "ping": ms}
        except Exception:
            return None


async def scan(ports):
    try:
        candidates = load_candidates()
    except Exception as e:
        print("clean IP source failed:", e)
        return []

    sem = asyncio.Semaphore(IP_SCAN_CONCURRENCY)
    tasks = [check(ip, port, sem) for ip in candidates for port in ports]
    results = [x for x in await asyncio.gather(*tasks) if x]

    # Keep every observed IP/port pair so remixer can use the exact port
    # required by a validated config. Never collapse an IP to one arbitrary port.
    unique = {(r["ip"], r["port"]): r for r in results}
    return sorted(unique.values(), key=lambda x: x["ping"])
