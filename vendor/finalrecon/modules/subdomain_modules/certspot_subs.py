#!/usr/bin/env python3

import asyncio
from json import loads

from modules.write_log import log_writer

R = "\033[31m"  # red
G = "\033[32m"  # green
C = "\033[36m"  # cyan
W = "\033[0m"  # white
Y = "\033[33m"  # yellow


async def certspot(hostname, session):
    subdomains = []
    error = None

    url = "https://api.certspotter.com/v1/issuances"
    cs_params = {
        "domain": hostname,
        "expand": "dns_names",
        "include_subdomains": "true",
    }

    try:
        async with session.get(url, params=cs_params) as resp:
            status = resp.status
            if status == 200:
                json_data = await resp.text()
                json_read = loads(json_data)
                for i in range(0, len(json_read)):
                    domains = json_read[i]["dns_names"]
                    subdomains.extend(domains)
            else:
                error = f"Status : {status}"
                log_writer(f"[certspot_subs] Status = {status}, expected 200")
    except asyncio.TimeoutError:
        error = "Request Timeout"
        log_writer(f"[certspot_subs] Exception = {error}")
    except Exception as exc:
        error = exc
        log_writer(f"[certspot_subs] Exception = {exc}")
    log_writer("[certspot_subs] Completed")
    return "CertSpotter", subdomains, error
