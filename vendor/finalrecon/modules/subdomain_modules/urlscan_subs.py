#!/usr/bin/env python3
import asyncio
from json import loads

from modules.write_log import log_writer

R = "\033[31m"  # red
G = "\033[32m"  # green
C = "\033[36m"  # cyan
W = "\033[0m"  # white
Y = "\033[33m"  # yellow


async def urlscan(hostname, session):
    subdomains = []
    error = None

    url = f"https://urlscan.io/api/v1/search/?q=domain:{hostname}"
    try:
        async with session.get(url) as resp:
            status = resp.status
            if status == 200:
                output = await resp.text()
                json_data = loads(output)["results"]
                for entry in json_data:
                    subdomains.append(entry["task"]["domain"])
            else:
                error = f"Status : {status}"
                log_writer(f"[urlscan_subs] Status = {status}, expected 200")
    except asyncio.TimeoutError:
        error = "Request Timeout"
        log_writer(f"[urlscan_subs] Exception = {error}")
    except Exception as exc:
        print(f"{R}[-] {C}UrlScan Exception : {W}{exc}")
    log_writer("[urlscan_subs] Completed")

    return "UrlScan", subdomains, error
