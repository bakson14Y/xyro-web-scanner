#!/usr/bin/env python3

import asyncio
from datetime import datetime, timezone
from json import load

from modules.export import export
from modules.write_log import log_writer

R = "\033[31m"  # red
G = "\033[32m"  # green
C = "\033[36m"  # cyan
W = "\033[0m"  # white
Y = "\033[33m"  # yellow
HEADER = "\033[1;35m"  # bold magenta


async def get_whois(domain, server):
    whois_result = {}
    reader, writer = await asyncio.open_connection(server, 43)
    writer.write((domain + "\r\n").encode())

    raw_resp = b""
    while True:
        chunk = await reader.read(4096)
        if not chunk:
            break
        raw_resp += chunk

    writer.close()
    await writer.wait_closed()
    raw_result = raw_resp.decode()

    if "No match for" in raw_result:
        whois_result = None

    res_parts = raw_result.split(">>>", 1)
    whois_result["whois"] = res_parts[0]
    return whois_result


def parse_whois(raw):
    IMPORTANT = {
        "Domain Name",
        "Registrar",
        "Creation Date",
        "Updated Date",
        "Registry Expiry Date",
        "Domain Status",
        "Name Server",
        "DNSSEC",
    }

    for line in raw.splitlines():
        color = W
        suffix = ""
        line = line.strip()
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key, val = key.strip(), val.strip()
        if not key or not val:
            continue
        if key not in IMPORTANT:
            continue
        if key == "Registry Expiry Date":
            try:
                expiry = datetime.fromisoformat(val.replace("Z", "+00:00"))
                days = (expiry - datetime.now(timezone.utc)).days
                color = R if days < 30 else Y if days < 90 else G
                suffix = f"({days} days)"
            except Exception:
                pass
        elif key == "DNSSEC" and val.lower() == "unsigned":
            color = R
        elif key == "Domain Status":
            val = val.split("https://")[0].strip()
        print(f"{C}{key.ljust(30)}{W} : {color}{val} {suffix}{W}")


def whois_lookup(domain, tld, script_path, output, data):
    result = {}
    db_path = f"{script_path}/whois_servers.json"
    with open(db_path, "r") as db_file:
        db_json = load(db_file)
    print(f"\n{HEADER}━━━ WHOIS {'━' * 30}{W}\n")

    try:
        whois_sv = db_json[tld]
        whois_info = asyncio.run(get_whois(f"{domain}.{tld}", whois_sv))
        parse_whois(whois_info["whois"])
        result.update(whois_info)
    except KeyError:
        print(f"{R}[-] Error : {C}This domain suffix is not supported.{W}")
        result.update({"Error": "This domain suffix is not supported."})
        log_writer("[whois] Exception = This domain suffix is not supported.")
    except Exception as exc:
        print(f"{R}[-] Error : {C}{exc}{W}")
        result.update({"Error": str(exc)})
        log_writer(f"[whois] Exception = {exc}")

    result.update({"exported": False})

    if output != "None":
        fname = f"{output['directory']}/whois.{output['format']}"
        output["file"] = fname
        data["module-whois"] = result
        export(output, data)
    log_writer("[whois] Completed")
