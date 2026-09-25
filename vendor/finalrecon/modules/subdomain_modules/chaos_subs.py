#!/usr/bin/env python3

import asyncio

from modules.write_log import log_writer

R = "\033[31m"  # red
G = "\033[32m"  # green
C = "\033[36m"  # cyan
W = "\033[0m"  # white
Y = "\033[33m"  # yellow


async def chaos(hostname, api_key, session):
    subdomains = []
    error = None

    if api_key is not None:
        url = f"https://dns.projectdiscovery.io/dns/{hostname}/subdomains"
        header = {"Authorization": api_key, "Connection": "close"}

        try:
            async with session.get(url, headers=header) as resp:
                status = resp.status
                if status == 200:
                    json_data = await resp.json()
                    raw = json_data.get("subdomains", [])
                    subdomains = [f"{sub}.{hostname}" for sub in raw]
                else:
                    error = f"Status : {status}"
                    log_writer(f"[chaos_subs] Status = {status}, expected 200")
        except asyncio.TimeoutError:
            error = "Request Timeout"
            log_writer(f"[chaos_subs] Exception = {error}")
        except Exception as exc:
            error = str(exc)
            log_writer(f"[chaos_subs] Exception = {exc}")
    else:
        error = "API key not configured"
        log_writer(f"[chaos_subs] {error}")

    log_writer("[chaos_subs] Completed")
    return "Chaos", subdomains, error
