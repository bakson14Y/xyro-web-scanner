#!/usr/bin/env python3

import asyncio
from json import loads

from modules.write_log import log_writer

R = "\033[31m"  # red
G = "\033[32m"  # green
C = "\033[36m"  # cyan
W = "\033[0m"  # white
Y = "\033[33m"  # yellow


async def shodan(hostname, api_key, session):
    subdomains = []
    error = None

    if api_key is not None:
        url = f"https://api.shodan.io/dns/domain/{hostname}?key={api_key}"
        try:
            async with session.get(url) as resp:
                status = resp.status
                if status == 200:
                    json_data = await resp.text()
                    json_read = loads(json_data)
                    domains = json_read["subdomains"]
                    tmp_list = []
                    for i in range(0, len(domains)):
                        tmp_list.append(f"{domains[i]}.{hostname}")
                    subdomains.extend(tmp_list)
                else:
                    error = f"Status : {status}"
                    log_writer(f"[shodan_subs] Status = {status}, expected 200")
        except asyncio.TimeoutError:
            error = "Request Timeout"
            log_writer(f"[shodan_subs] Exception = {error}")
        except Exception as exc:
            error = exc
            log_writer(f"[shodan_subs] Exception = {exc}")
    else:
        error = "API key not configured"
        log_writer(f"[shodan_subs] {error}")
    log_writer("[shodan_subs] Completed")

    return "Shodan", subdomains, error
