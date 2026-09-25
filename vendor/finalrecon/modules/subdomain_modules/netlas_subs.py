#!/usr/bin/env python3
import asyncio
from json import loads

from modules.write_log import log_writer

R = "\033[31m"  # red
G = "\033[32m"  # green
C = "\033[36m"  # cyan
W = "\033[0m"  # white
Y = "\033[33m"  # yellow


async def netlas(hostname, api_key, session):
    subdomains = []
    error = None

    if api_key is not None:
        url = "https://app.netlas.io/api/domains/download/"
        header = {"X-API-Key": api_key}
        payload = {
            "q": f"domain: *.{hostname}",
            "fields": ["domain"],
            "source_type": "include",
            "size": "200",
        }

        try:
            async with session.post(url, headers=header, data=payload) as resp:
                status = resp.status
                if status == 200:
                    json_data = loads(await resp.text())
                    for entry in json_data:
                        subdomain = entry["data"]["domain"]
                        subdomains.append(subdomain)
                else:
                    error = f"Status : {status}"
                    log_writer(f"[netlas_subs] Status = {status}, expected 200")
        except asyncio.TimeoutError:
            error = "Request Timeout"
            log_writer(f"[netlas_subs] Exception = {error}")
        except Exception as exc:
            error = exc
            log_writer(f"[netlas_subs] Exception = {exc}")
    else:
        error = "API key not configured"
        log_writer(f"[netlas_subs] {error}")
    log_writer("[netlas_subs] Completed")
    return "Netlas", subdomains, error
