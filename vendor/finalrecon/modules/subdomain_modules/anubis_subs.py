#!/usr/bin/env python3

import asyncio
from json import loads

from modules.write_log import log_writer

R = "\033[31m"  # red
G = "\033[32m"  # green
C = "\033[36m"  # cyan
W = "\033[0m"  # white
Y = "\033[33m"  # yellow


async def anubisdb(hostname, session):
    subdomains = []
    error = None
    url = f"https://anubisdb.com/anubis/subdomains/{hostname}"
    try:
        async with session.get(url) as resp:
            status = resp.status
            if status == 200:
                output = await resp.text()
                subdomains.extend(loads(output))
            elif status == 300:
                error = f"Status : {status}, no subdomains found"
                log_writer(f"[anubis_subs] Status = {status}, no subdomains found")
            else:
                error = f"Status : {status}"
                log_writer(f"[anubis_subs] Status = {status}, expected 200")
                log_writer(f"[anubis_subs] Exception = {await resp.text()}")
    except asyncio.TimeoutError:
        error = "Request Timeout"
    except Exception as exc:
        error = exc
    log_writer(f"[anubis_subs] Exception = {error}")
    log_writer("[anubis_subs] Completed")

    return "AnubisDB", subdomains, error
