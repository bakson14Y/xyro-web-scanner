import hashlib
import json
import re
import time
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

TOOLS = ("recon", "gau", "katana", "cariddi", "finalrecon", "snallygaster", "arjun", "dalfox", "ghauri")
PROFILES = {
    "recon": ("recon", "gau", "katana", "cariddi", "finalrecon"),
    "audit": TOOLS,
}
LABELS = {"recon": "HTTP · TLS · Cookies", "gau": "История URL", "katana": "Карта сайта",
          "cariddi": "JS · секреты · endpoints", "finalrecon": "DNS · заголовки · сертификат",
          "snallygaster": "Открытые служебные файлы", "arjun": "Скрытые параметры",
          "dalfox": "XSS", "ghauri": "SQL injection"}

def canonical_url(value):
    value = str(value).strip()
    if any(ord(c) < 33 for c in value) or "\\" in value:
        raise ValueError("URL содержит пробелы или управляющие символы")
    u = urlsplit(value)
    if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password:
        raise ValueError("Введите полный http(s) URL без логина и пароля")
    port = u.port  # validates port range
    host = u.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    if not re.fullmatch(r"[a-z0-9.:-]+", host):
        raise ValueError("Некорректный хост")
    if ":" in host:
        host = "[" + host + "]"
    default = 443 if u.scheme == "https" else 80
    netloc = host + (":" + str(port) if port and port != default else "")
    return urlunsplit((u.scheme, netloc, u.path or "/", u.query, ""))

def origin(url):
    p = urlsplit(canonical_url(url))
    return p.scheme, p.hostname, p.port or (443 if p.scheme == "https" else 80)

class Scope:
    def __init__(self, target):
        self.target = canonical_url(target)
        self.origin = origin(self.target)

    def contains(self, url):
        try:
            return origin(url) == self.origin
        except (ValueError, UnicodeError):
            return False

    def require(self, url):
        if not self.contains(url):
            raise ValueError("Вне заданного origin: " + str(url)[:180])
        return canonical_url(url)

def validate_config(data):
    if not isinstance(data, dict):
        raise ValueError("Ожидается объект настроек")
    target = canonical_url(data.get("target", ""))
    profile = data.get("profile", "recon")
    if profile not in PROFILES:
        raise ValueError("Неизвестный профиль")
    result = {"target": target, "profile": profile}
    for key, default, low, high in (("rps", 3, 1, 20), ("depth", 3, 1, 10),
                                    ("max_urls", 80, 1, 2000), ("stage_timeout", 180, 15, 3600)):
        value = int(data.get(key, default))
        if not low <= value <= high:
            raise ValueError(f"{key}: допустимо {low}–{high}")
        result[key] = value
    return result

def atomic_json(path, value):
    path = Path(path)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(path)

def finding(tool, title, url, evidence, severity="info", confidence="candidate"):
    identity = "|".join((tool, title, url, str(evidence)))
    return {"id": hashlib.sha256(identity.encode()).hexdigest()[:16], "tool": tool,
            "title": title, "url": url, "evidence": str(evidence)[:4000],
            "severity": severity, "confidence": confidence, "at": time.time()}

ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
def plain(value):
    return ANSI.sub("", str(value))
