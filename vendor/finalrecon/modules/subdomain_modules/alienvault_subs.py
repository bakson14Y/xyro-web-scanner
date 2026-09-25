#!/usr/bin/env python3

import asyncio
from json import loads

from modules.write_log import log_writer

R = "\033[31m"  # red
G = "\033[32m"  # green
C = "\033[36m"  # cyan
W = "\033[0m"  # white
Y = "\033[33m"  # yellow


async def alienvault(hostname, api_key, session):
    error = None
    subdomains = []
    if api_key is not None:
        header = {"X-OTX-API-KEY": api_key}
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{hostname}/passive_dns"
        try:
            async with session.get(url, headers=header) as resp:
                status = resp.status
                if status == 200:
                    output = await resp.text()
                    json_data = loads(output)["passive_dns"]
                    for entry in json_data:
                        subdomains.append(entry["hostname"])
                else:
                    error = f"Status : {status}"
                    log_writer(f"[alienvault_subs] Status = {status}, expected 200")
                    log_writer(f"[alienvault_subs] Exception = {await resp.text()}")
        except asyncio.TimeoutError:
            error = "Request Timeout"
        except Exception as exc:
            error = exc
        log_writer(f"[alienvault_subs] Exception = {error}")
        log_writer("[alienvault_subs] Completed")
    else:
        error = "API key not configured"
        log_writer(f"[alienvault_subs] {error}")

    return "Alienvault", subdomains, error
