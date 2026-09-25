#!/usr/bin/env python3

import asyncio
import re

from modules.write_log import log_writer

R = "\033[31m"
G = "\033[32m"
C = "\033[36m"
W = "\033[0m"
Y = "\033[33m"


async def github(hostname, api_key, session):
    subdomains = []
    error = None

    if api_key is not None:
        header = {
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/vnd.github.text-match+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        params = {
            "q": hostname,
            "per_page": 100,
        }
        pattern = re.compile(rf"(?:[a-zA-Z0-9_*-]+\.)+{re.escape(hostname)}")

        try:
            for page in range(1, 10):
                params = {"q": hostname, "per_page": 100, "page": page}
                async with session.get(
                    "https://api.github.com/search/code",
                    headers=header,
                    params=params,
                ) as resp:
                    status = resp.status
                    if status == 403:
                        error = "Rate limited"
                        log_writer("[github_subs] Rate limited")
                        break
                    if status != 200:
                        error = f"Status = {status}"
                        log_writer(f"[github_subs] Status = {status}, expected 200")
                        break
                    json_data = await resp.json()
                    items = json_data.get("items", [])
                    if not items:
                        break
                    for item in items:
                        for match in item.get("text_matches", []):
                            matches = pattern.findall(match.get("fragment", ""))
                            subdomains.extend(matches)
                            subdomains = [
                                s
                                for s in subdomains
                                if not re.search(r"(?:^|\.)[0-9A-Fa-f]{2}[A-Z]", s)
                            ]
                await asyncio.sleep(0.1)
        except asyncio.TimeoutError:
            error = "Request Timeout"
            log_writer(f"[github_subs] Exception = {error}")
        except Exception as exc:
            error = str(exc)
            log_writer(f"[github_subs] Exception = {exc}")
    else:
        error = "API key not configured"
        log_writer(f"[github_subs] {error}")

    log_writer("[github_subs] Completed")
    return "GitHub", subdomains, error
