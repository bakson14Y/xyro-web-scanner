#!/usr/bin/env python3
import asyncio
from base64 import urlsafe_b64encode
from datetime import datetime, timedelta

from modules.write_log import log_writer

R = "\033[31m"  # red
G = "\033[32m"  # green
C = "\033[36m"  # cyan
W = "\033[0m"  # white
Y = "\033[33m"  # yellow


async def hunter(hostname, api_key, session):
    subdomains = []
    error = None

    if api_key is not None:
        url = "https://api.hunter.how/search"
        query = f'domain.suffix=="{hostname}"'
        query64 = urlsafe_b64encode(query.encode("utf-8")).decode("ascii")
        start_year = datetime.today().year - 1
        start_month = datetime.today().month
        start_day = datetime.today().day
        try:
            start_date = datetime.strptime(
                f"{start_year}-{start_month}-{start_day}", "%Y-%m-%d"
            ).strftime("%Y-%m-%d")
        except ValueError:
            # handle leap year
            start_date = datetime.strptime(
                f"{start_year}-{start_month}-{start_day - 1}", "%Y-%m-%d"
            ).strftime("%Y-%m-%d")
        end_date = (datetime.today() - timedelta(days=2)).strftime("%Y-%m-%d")

        payload = {
            "api-key": api_key,
            "query": query64,
            "page": 1,
            "page_size": 1000,
            "start_time": start_date,
            "end_time": end_date,
        }
        try:
            async with session.get(url, params=payload) as resp:
                status = resp.status
                if status == 200:
                    json_data = await resp.json()
                    resp_code = json_data["code"]
                    if resp_code != 200:
                        resp_msg = json_data["message"]
                        error = f"{resp_code}, {resp_msg}"
                        log_writer(f"[hunter_subs] Status = {resp_code}, expected 200")
                    else:
                        subdomain_list = json_data["data"]["list"]
                        for entry in subdomain_list:
                            subdomains.append(entry["domain"])
                else:
                    error = f"Status : {status}"
                    log_writer(f"[hunter_subs] Status = {status}, expected 200")
        except asyncio.TimeoutError:
            error = "Request Timeout"
            log_writer(f"[hunter_subs] Exception = {error}")
        except Exception as exc:
            error = exc
            log_writer(f"[hunter_subs] Exception = {exc}")
    else:
        error = "API key not configured"
        log_writer(f"[hunter_subs] {error}")
    log_writer("[hunter_subs] Completed")

    return "Hunter", subdomains, error
