#!/usr/bin/env python3

import asyncio

import dns.asyncresolver

from modules.export import export
from modules.write_log import log_writer

R = "\033[31m"  # red
G = "\033[32m"  # green
C = "\033[36m"  # cyan
W = "\033[0m"  # white
Y = "\033[33m"  # yellow
HEADER = "\033[1;35m"  # bold magenta


def dnsrec(domain, dns_servers, output, data):
    result = {}
    print(f"\n{HEADER}━━━ DNS Enum {'━' * 30}{W}\n")

    DNS_GROUPS = {
        "core": ["A", "AAAA", "CNAME", "PTR", "NS", "SOA", "MX"],
        "security": [
            "CAA",
            "DNSKEY",
            "CDNSKEY",
            "CDS",
            "DS",
            "RRSIG",
            "NSEC",
            "NSEC3",
            "NSEC3PARAM",
            "TLSA",
            "SSHFP",
            "SMIMEA",
            "OPENPGPKEY",
            "TA",
            "DLV",
            "SIG",
            "KEY",
        ],
        "mail": ["TXT", "SRV", "NAPTR", "URI"],
        "network": ["IPSECKEY", "HIP", "LOC", "SVCB", "HTTPS", "APL", "AFSDB", "KX"],
        "zone": ["DNAME", "CSYNC", "ZONEMD", "TKEY", "TSIG"],
        "info": ["HINFO", "RP", "CERT", "DHCID", "EUI48", "EUI64", "HINFO"],
    }

    full_ans = []

    res = dns.asyncresolver.Resolver(configure=False)
    res.nameservers = [sv.strip() for sv in dns_servers.split(",")]

    async def fetch_records(res, domain, record):
        answer = await res.resolve(domain, record)
        return answer

    for dns_grp in DNS_GROUPS:
        group_printed = False
        for dns_record in DNS_GROUPS.get(dns_grp):
            try:
                ans = asyncio.run(fetch_records(res, domain, dns_record))
                for record_data in ans:
                    full_ans.append(f"{dns_record} : {record_data.to_text()}")
                    if not group_printed:
                        print()
                        group_printed = True
                    if dns_grp == "security":
                        print(f"{Y}{dns_record.ljust(10)}{W} : {record_data.to_text()}")
                    else:
                        print(f"{G}{dns_record.ljust(10)}{W} : {record_data.to_text()}")
            except dns.resolver.NoAnswer as exc:
                log_writer(f"[dns] Exception = {exc}")
            except dns.resolver.NoMetaqueries as exc:
                log_writer(f"[dns] Exception = {exc}")
            except dns.resolver.NoNameservers as exc:
                log_writer(f"[dns] Exception = {exc}")
            except dns.resolver.NXDOMAIN as exc:
                log_writer(f"[dns] Exception = {exc}")
                print(f"{R}[-]{W} DNS Records Not Found!")
                if output != "None":
                    result.setdefault("dns", ["DNS Records Not Found"])
                return

    for entry in full_ans:
        if output != "None":
            result.setdefault("dns", []).append(entry)

    dmarc_target = f"_dmarc.{domain}"
    try:
        dmarc_ans = asyncio.run(fetch_records(res, dmarc_target, "TXT"))
        for entry in dmarc_ans:
            print(f"{Y}{'DMARC'.ljust(10)}{W} : {entry.to_text()}")
            if output != "None":
                result.setdefault("dmarc", []).append(f"DMARC : {entry.to_text()}")
    except dns.resolver.NoAnswer as exc:
        log_writer(f"[dns.dmarc] Exception = {exc}")
    except dns.resolver.NoMetaqueries as exc:
        log_writer(f"[dns.dmarc] Exception = {exc}")
    except dns.resolver.NoNameservers as exc:
        log_writer(f"[dns.dmarc] Exception = {exc}")
    except dns.resolver.NXDOMAIN as exc:
        log_writer(f"[dns.dmarc] Exception = {exc}")
        print(f"\n{R}[-] {C}DMARC Record Not Found!{W}")
        if output != "None":
            result.setdefault("dmarc", ["DMARC Record Not Found!"])

    result.update({"exported": False})

    if output != "None":
        data["module-DNS Enumeration"] = result
        fname = f"{output['directory']}/dns_records.{output['format']}"
        output["file"] = fname
        export(output, data)
    log_writer("[dns] Completed")
