#!/usr/bin/env python3
import asyncio
from json import loads

from modules.write_log import log_writer

R = "\033[31m"  # red
G = "\033[32m"  # green
C = "\033[36m"  # cyan
W = "\033[0m"  # white
Y = "\033[33m"  # yellow


async def virust(hostname, api_key, session):
    subdomains = []
    error = None

    if api_key is not None:
        url = f"https://www.virustotal.com/api/v3/domains/{hostname}/subdomains"
        vt_headers = {"x-apikey": api_key}
        try:
            async with session.get(url, headers=vt_headers) as resp:
                status = resp.status
                if status == 200:
                    json_data = await resp.text()
                    json_read = loads(json_data)
                    domains = json_read["data"]
                    tmp_list = []
                    for i in range(0, len(domains)):
                        tmp_list.append(domains[i]["id"])
                    subdomains.extend(tmp_list)
                else:
                    error = f"Status : {status}"
                    log_writer(f"[virustotal_subs] Status = {status}")
        except asyncio.TimeoutError:
            error = "Request Timeout"
            log_writer(f"[virustotal_subs] Exception = {error}")
        except Exception as exc:
            print(f"{R}[-] {C}VirusTotal Exception : {W}{exc}")
            log_writer(f"[virustotal_subs] Exception = {exc}")
    else:
        error = "API key not configured"
        log_writer(f"[virustotal_subs] {error}")
    log_writer("[virustotal_subs] Completed")

    return "VirusTotal", subdomains, error
