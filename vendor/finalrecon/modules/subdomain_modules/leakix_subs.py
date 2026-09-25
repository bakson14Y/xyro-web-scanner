#!/usr/bin/env python3

import asyncio

from modules.write_log import log_writer

R = "\033[31m"
G = "\033[32m"
C = "\033[36m"
W = "\033[0m"
Y = "\033[33m"


async def leakix(hostname, api_key, session):
    subdomains = []
    error = None

    if api_key is not None:
        url = f"https://leakix.net/api/subdomains/{hostname}"
        header = {
            "api-key": api_key,
            "accept": "application/json",
        }

        try:
            async with session.get(url, headers=header) as resp:
                status = resp.status
                if status == 200:
                    json_data = await resp.json()
                    subdomains = [
                        entry["subdomain"]
                        for entry in json_data
                        if "subdomain" in entry
                    ]
                else:
                    error = f"Status : {status}"
                    log_writer(f"[leakix_subs] Status = {status}, expected 200")
        except asyncio.TimeoutError:
            error = "Request Timeout"
            log_writer(f"[leakix_subs] Exception = {error}")
        except Exception as exc:
            error = str(exc)
            log_writer(f"[leakix_subs] Exception = {exc}")
    else:
        error = "API key not configured"
        log_writer(f"[leakix_subs] {error}")

    log_writer("[leakix_subs] Completed")
    return "LeakIX", subdomains, error
