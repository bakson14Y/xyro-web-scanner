import http.client
import ssl
import time
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit
from .model import finding

class RedirectOutsideScope(ValueError):
    """A valid response whose redirect destination has not been authorized."""
    def __init__(self, source, destination, status):
        self.source = source
        self.destination = destination
        self.status = status
        super().__init__(f'HTTP {status}: переход с {source} на {destination} остановлен: адрес вне области проверки')

class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls = []
    def handle_starttag(self, tag, attrs):
        for key, value in attrs:
            if key in ("href", "src", "action") and value:
                self.urls.append(value)

def request(scope, url, timeout=10, headers=None, method='GET'):
    """Bounded GET; every redirect is checked before issuing another request."""
    request_headers = dict(headers or {})
    for _ in range(6):
        u = urlsplit(scope.require(url))
        cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
        import certifi
        connection = cls(u.hostname, u.port, timeout=timeout, context=ssl.create_default_context(cafile=certifi.where())) if u.scheme == 'https' else cls(u.hostname, u.port, timeout=timeout)
        try:
            connection.request(method, u.path + ("?" + u.query if u.query else ""),
                               headers={"User-Agent": "XYRO/1.5 (+authorized-assessment)", "Accept-Encoding": "identity", **request_headers})
            response = connection.getresponse()
            response_headers = response.getheaders()
            body = response.read(1024 * 1024).decode("utf-8", "replace")
            if response.status in (301, 302, 303, 307, 308):
                location = response.getheader("Location")
                if location:
                    destination = urljoin(url, location)
                    if not scope.contains(destination):
                        raise RedirectOutsideScope(url, destination, response.status)
                    url = scope.require(destination)
                    continue
            return response.status, response_headers, body, url
        finally:
            connection.close()
    raise ValueError("Слишком много перенаправлений")

def run(scope, config, add, add_url, check):
    pending = list(scope.targets)
    seen = set()
    # Baseline crawler is deliberately small; Katana owns depth crawling.
    while pending and len(seen) < min(config["max_urls"], 10):
        check()
        url = pending.pop(0)
        if url in seen:
            continue
        seen.add(url)
        try:
            status, pairs, body, final = request(scope, url, headers=config.get('headers', {}))
        except RedirectOutsideScope as exc:
            add_url(exc.source)
            add(finding('recon', 'Редирект за пределы области', exc.source,
                        str(exc), confidence='observed',
                        redirect_url=exc.destination,
                        remediation='Чтобы проверить конечный сайт, начните новую проверку с URL: '
                                    + exc.destination + '. Для проверки обоих адресов добавьте конечный URL '
                                    'в дополнительные начальные URL. Схема, хост и порт учитываются отдельно.'))
            time.sleep(1 / config['rps'])
            continue
        add_url(final)
        headers = {k.lower(): v for k, v in pairs}
        if url == scope.target:
            add(finding("recon", "HTTP", final, f"Статус {status}; Server: {headers.get('server', 'не указан')}", confidence="observed"))
            for header in ("content-security-policy", "x-content-type-options", "referrer-policy"):
                if header not in headers:
                    add(finding("recon", "Нет " + header, final, "Заголовок отсутствует в ответе; оценка зависит от контекста", "low", "observed"))
            if final.startswith("https://") and "strict-transport-security" not in headers:
                add(finding("recon", "Нет HSTS", final, "Strict-Transport-Security отсутствует", "low", "observed"))
            if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
                add(finding("recon", "Не задана защита от встраивания", final, "Нет X-Frame-Options и CSP frame-ancestors", "low"))
            for k, v in pairs:
                if k.lower() == "set-cookie":
                    name = v.split("=", 1)[0]
                    attrs = {x.strip().split("=", 1)[0].lower() for x in v.split(";")[1:]}
                    missing = {"secure", "httponly", "samesite"} - attrs
                    if missing:
                        add(finding("recon", "Атрибуты cookie: " + name, final, "Отсутствуют: " + ", ".join(sorted(missing)), "low"))
        if "html" in headers.get("content-type", ""):
            parser = Links()
            parser.feed(body)
            for item in parser.urls:
                candidate = urljoin(final, item)
                if scope.contains(candidate):
                    add_url(candidate)
                    # Do not automatically submit forms or invoke obvious state-changing routes.
                    if len(pending) < config["max_urls"] and not any(x in candidate.lower() for x in ("logout", "delete", "remove", "signout")):
                        pending.append(candidate)
        time.sleep(1 / config["rps"])
