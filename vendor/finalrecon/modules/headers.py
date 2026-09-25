#!/usr/bin/env python3

import requests

from modules.export import export
from modules.write_log import log_writer

requests.packages.urllib3.disable_warnings()

R = "\033[31m"  # red
G = "\033[32m"  # green
C = "\033[36m"  # cyan
W = "\033[0m"  # white
Y = "\033[33m"  # yellow
HEADER = "\033[1;35m"  # bold magenta

SECURITY_HEADERS = {
    "X-Frame-Options",
    "X-XSS-Protection",
    "Content-Security-Policy",
    "Content-Security-Policy-Report-Only",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
}

REQUIRED_HEADERS = {
    "Strict-Transport-Security": "HSTS",
    "X-Content-Type-Options": "X-Content-Type-Options",
    "X-Frame-Options": "X-Frame-Options",
    "Content-Security-Policy": "CSP",
    "Referrer-Policy": "Referrer-Policy",
}

COOKIE_ATTRS = ["Secure", "HttpOnly", "SameSite", "Path", "Domain", "Expires"]


def headers(target, output, data):
    result = {}
    print(f"\n{HEADER}━━━ Headers {'━' * 30}{W}\n")
    try:
        rqst = requests.get(target, verify=False, timeout=10)
        hdrs = rqst.headers

        general = {
            k: v
            for k, v in hdrs.items()
            if k not in SECURITY_HEADERS and k != "Set-Cookie"
        }
        print(f"{G}❯ General{W}\n")
        for key, val in general.items():
            print(f"   {C}{key.ljust(30)}{W} : {val}")
            if output != "None":
                result[key] = val

        sec = {k: v for k, v in hdrs.items() if k in SECURITY_HEADERS}
        if sec:
            print(f"\n{Y}❯ Security{W}\n")
            for key, val in sec.items():
                print(f"  {Y}{key.ljust(30)}{W} : {val}")
                if output != "None":
                    result[key] = val

        missing = [
            label for header, label in REQUIRED_HEADERS.items() if header not in hdrs
        ]
        if missing:
            print(f"\n{R}❯ Missing{W}\n")
            for label in missing:
                print(f"   {R}{label}{W}")

        cookies = rqst.headers.get("Set-Cookie", "")
        if cookies:
            print(f"\n{Y}❯ Cookies{W}\n")
            for cookie in rqst.raw.headers.getlist("Set-Cookie"):
                parts = [p.strip() for p in cookie.split(";")]
                name = parts[0].split("=")[0]
                attrs = {
                    p.split("=")[0].strip(): p.split("=")[1].strip()
                    if "=" in p
                    else "✓"
                    for p in parts[1:]
                }
                secure = f"{G}✓{W}" if "Secure" in attrs else f"{R}✗{W}"
                httponly = f"{G}✓{W}" if "HttpOnly" in attrs else f"{R}✗{W}"
                samesite = attrs.get("SameSite", f"{R}Not Set{W}")
                print(
                    f"   {C}{name.ljust(20)}{W} Secure={secure} HttpOnly={httponly} SameSite={samesite}"
                )
                if output != "None":
                    result.setdefault("cookies", []).append(cookie)

    except Exception as exc:
        print(f"\n{R}[-] {C}Exception : {W}{exc}\n")
        if output != "None":
            result.update({"Exception": str(exc)})
        log_writer(f"[headers] Exception = {exc}")
    result.update({"exported": False})

    if output != "None":
        fname = f"{output['directory']}/headers.{output['format']}"
        output["file"] = fname
        data["module-headers"] = result
        export(output, data)
    log_writer("[headers] Completed")
