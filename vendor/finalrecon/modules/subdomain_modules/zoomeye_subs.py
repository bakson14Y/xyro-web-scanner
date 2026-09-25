#!/usr/bin/env python3

import asyncio

from modules.write_log import log_writer

R = "\033[31m"  # red
G = "\033[32m"  # green
C = "\033[36m"  # cyan
W = "\033[0m"  # white
Y = "\033[33m"  # yellow


async def zoomeye(hostname, api_key, session):
    subdomains = []
    error = None

    if api_key is not None:
        url = f"https://api.zoomeye.ai/domain/search?q={hostname}&type=0"
        header = {"API-KEY": api_key, "User-Agent": "curl"}

        try:
            async with session.get(url, headers=header) as resp:
                status = resp.status
                if status == 200:
                    json_data = await resp.json()
                    subdomain_list = json_data["list"]
                    subdomains = [subd["name"] for subd in subdomain_list]
                else:
                    error = f"Status : {status}"
                    log_writer(f"[zoomeye_subs] Status = {status}, expected 200")
        except asyncio.TimeoutError:
            error = "Request Timeout"
            log_writer(f"[zoomeye_subs] Exception = {error}")
        except Exception as exc:
            print(f"{R}[-] {C}zoomeye Exception : {W}{exc}")
            log_writer(f"[zoomeye_subs] Exception = {exc}")
    else:
        error = "API key not configured"
        log_writer(f"[zoomeye_subs] {error}")
    log_writer("[zoomeye_subs] Completed")

    return "ZoomEye", subdomains, error
