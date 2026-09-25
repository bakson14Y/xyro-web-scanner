#!/usr/bin/env python3

import asyncio

from modules.write_log import log_writer

R = "\033[31m"  # red
G = "\033[32m"  # green
C = "\033[36m"  # cyan
W = "\033[0m"  # white
Y = "\033[33m"  # yellow


async def bevigil(hostname, api_key, session):
    subdomains = []
    error = None

    if api_key is not None:
        url = f"https://osint.bevigil.com/api/{hostname}/subdomains/"
        header = {"X-Access-Token": api_key}

        try:
            async with session.get(url, headers=header) as resp:
                status = resp.status
                if status == 200:
                    json_data: list = await resp.json()
                    subdomains = json_data.get("subdomains")
                else:
                    error = f"Status : {status}"
                    log_writer(f"[bevigil_subs] Status = {status}, expected 200")
        except asyncio.TimeoutError:
            error = "Request Timeout"
            log_writer(f"[bevigil_subs] Exception = {error}")
        except Exception as exc:
            error = exc
            log_writer(f"[bevigil_subs] Exception = {exc}")
    else:
        error = "API key not configured"
        log_writer("[bevigil_subs] API key not found")
    log_writer("[bevigil_subs] Completed")

    return "BeVigil", subdomains, error
