#!/usr/bin/env python3
import asyncio

from modules.write_log import log_writer

R = "\033[31m"  # red
G = "\033[32m"  # green
C = "\033[36m"  # cyan
W = "\033[0m"  # white
Y = "\033[33m"  # yellow


async def hackertgt(hostname, session):
    subdomains = []
    error = None
    url = f"https://api.hackertarget.com/hostsearch/?q={hostname}"
    try:
        async with session.get(url) as resp:
            status = resp.status
            if status == 200:
                data = await resp.text()
                data_list = data.split("\n")
                tmp_list = []
                for line in data_list:
                    subdomain = line.split(",")[0]
                    tmp_list.append(subdomain)
                subdomains.extend(tmp_list)
            else:
                error = f"Status : {status}"
                log_writer(f"[htarget_subs] Status = {status}, expected 200")
    except asyncio.TimeoutError:
        error = "Request Timeout"
        log_writer(f"[htarget_subs] Exception = {error}")
    except Exception as exc:
        error = exc
        log_writer(f"[htarget_subs] Exception = {exc}")
    log_writer("[htarget_subs] Completed")

    return "Hackertarget", subdomains, error
