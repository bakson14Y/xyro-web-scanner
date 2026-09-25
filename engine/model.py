import hashlib
import ipaddress
import json
import re
import time
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

VERSION = '1.5.0'
TOOLS = ('recon', 'subfinder', 'dns', 'ports', 'webprobe', 'gau', 'katana', 'discovery', 'cariddi', 'finalrecon', 'snallygaster', 'arjun', 'nuclei', 'dalfox', 'ghauri')
PROFILES = {
    'quick': ('recon', 'dns', 'webprobe', 'nuclei'),
    'recon': ('recon', 'subfinder', 'dns', 'ports', 'webprobe', 'gau', 'katana', 'discovery', 'cariddi', 'finalrecon'),
    'audit': TOOLS,
    'custom': TOOLS,
}
LABELS = {'recon': 'HTTP · TLS · Cookies', 'subfinder': 'Пассивный поиск поддоменов',
          'dns': 'DNS · A/AAAA/MX/NS/TXT/CAA', 'ports': 'TCP-сервисы', 'webprobe': 'Живые сайты · технологии · TLS',
          'gau': 'Архивные URL', 'katana': 'Обход сайта · JS · формы', 'discovery': 'Пути · robots · sitemap · API',
          'cariddi': 'JS · секреты · endpoints', 'finalrecon': 'DNS · заголовки · сертификат',
          'snallygaster': 'Открытые служебные файлы', 'arjun': 'Скрытые параметры',
          'nuclei': 'CVE · экспозиции · конфигурация', 'dalfox': 'XSS', 'ghauri': 'SQL injection'}
BUILTIN_TOOLS = ('recon', 'dns', 'ports', 'webprobe', 'discovery')
NATIVE_TOOLS = ('katana', 'cariddi', 'gau', 'dalfox', 'nuclei', 'subfinder')
SEVERITIES = ('critical', 'high', 'medium', 'low', 'info')

def canonical_url(value):
    value = str(value).strip()
    if any(ord(c) < 33 for c in value) or '\\' in value:
        raise ValueError('URL содержит пробелы или управляющие символы')
    u = urlsplit(value)
    if u.scheme not in ('http', 'https') or not u.hostname or u.username or u.password:
        raise ValueError('Введите полный http(s) URL без логина и пароля')
    port = u.port
    host = u.hostname.encode('idna').decode('ascii').lower().rstrip('.')
    if not re.fullmatch(r'[a-z0-9.:-]+', host): raise ValueError('Некорректный хост')
    if ':' in host:
        ipaddress.IPv6Address(host)
        host = '[' + host + ']'
    default = 443 if u.scheme == 'https' else 80
    return urlunsplit((u.scheme, host + (':' + str(port) if port and port != default else ''), u.path or '/', u.query, ''))

def origin(url):
    p = urlsplit(canonical_url(url))
    return p.scheme, p.hostname, p.port or (443 if p.scheme == 'https' else 80)

def host_url(scheme, host, port):
    return canonical_url(f'{scheme}://{"["+host+"]" if ":" in host else host}:{port}/')

class Scope:
    def __init__(self, target, targets=(), include_subdomains=False, ports=(), exclude_paths=()):
        self.target = canonical_url(target)
        self.targets = list(dict.fromkeys([self.target] + [canonical_url(t) for t in targets]))
        self.origin = origin(self.target)
        self.origins = {origin(t) for t in self.targets}
        self.include_subdomains = include_subdomains
        self.ports = set(ports)
        self.exclude_paths = tuple(exclude_paths)
        self.hosts = {x[1] for x in self.origins}

    def host_allowed(self, host):
        host = str(host).encode('idna').decode('ascii').lower().rstrip('.')
        return host in self.hosts or (self.include_subdomains and any(host.endswith('.' + h) for h in self.hosts if ':' not in h))

    def contains(self, url):
        try:
            scheme, host, port = origin(url)
            if any(urlsplit(url).path.startswith(prefix) for prefix in self.exclude_paths): return False
            if (scheme, host, port) in self.origins: return True
            return self.host_allowed(host) and (port in self.ports or
                (self.include_subdomains and any((scheme, port) == (s, p) for s, _, p in self.origins)))
        except (ValueError, UnicodeError): return False

    def require(self, url):
        if not self.contains(url): raise ValueError('Вне заданной области: ' + str(url)[:180])
        return canonical_url(url)

    def regex(self):
        hosts = '|'.join(re.escape(h) for h in sorted(self.hosts))
        prefix = r'(?:[a-zA-Z0-9-]+\.)*' if self.include_subdomains else ''
        return r'^https?://' + prefix + '(?:' + hosts + r')(?::[0-9]+)?(?:/|$)'

def _list(value):
    if value is None: return []
    if isinstance(value, str): return [s.strip() for s in re.split(r'[,\n]', value) if s.strip()]
    if not isinstance(value, (tuple, list)): raise ValueError('Ожидается список или строка')
    return list(value)

def validate_config(data):
    if not isinstance(data, dict): raise ValueError('Ожидается объект настроек')
    targets = _list(data.get('targets', []))
    target = canonical_url(data.get('target') or (targets[0] if targets else ''))
    targets = list(dict.fromkeys([target] + [canonical_url(t) for t in targets]))
    if len(targets) > 30: raise ValueError('Максимум 30 начальных URL')
    profile = data.get('profile', 'recon')
    if profile not in PROFILES: raise ValueError('Неизвестный профиль')
    requested = _list(data.get('tools', PROFILES[profile]))
    if not requested or any(t not in TOOLS for t in requested): raise ValueError('Выберите известные модули проверки')
    result = {'target': target, 'targets': targets, 'profile': profile, 'tools': [t for t in TOOLS if t in requested]}
    for key, default, low, high in (('rps', 5, 1, 50), ('depth', 3, 1, 15), ('max_urls', 500, 1, 20000),
                                    ('stage_timeout', 300, 15, 7200), ('concurrency', 3, 1, 8), ('max_hosts', 40, 1, 250)):
        try: value = int(data.get(key, default))
        except (TypeError, ValueError): raise ValueError(f'{key}: ожидается число') from None
        if not low <= value <= high: raise ValueError(f'{key}: допустимо {low}–{high}')
        result[key] = value
    result['include_subdomains'] = data.get('include_subdomains', False) is True
    if result['include_subdomains'] and any('.' not in urlsplit(t).hostname for t in targets):
        raise ValueError('Для поддоменов укажите полное доменное имя')
    try: ports = sorted(set(int(p) for p in _list(data.get('ports', []))))
    except (ValueError, TypeError): raise ValueError('Порты: числа через запятую') from None
    if len(ports) > 100 or any(not 1 <= p <= 65535 for p in ports): raise ValueError('Допустимо до 100 портов 1–65535')
    result['ports'] = ports
    result['exclude_paths'] = _list(data.get('exclude_paths', ['/logout', '/signout']))
    if len(result['exclude_paths']) > 50 or any(not p.startswith('/') or len(p) > 300 for p in result['exclude_paths']):
        raise ValueError('Исключения: до 50 путей, начинающихся с /')
    result['custom_paths'] = _list(data.get('custom_paths', []))
    if len(result['custom_paths']) > 500 or any(not p.startswith('/') or p.startswith('//') or len(p) > 300 or any(ord(c)<33 for c in p) for p in result['custom_paths']):
        raise ValueError('Словарь: до 500 относительных путей /path')
    preset = data.get('nuclei_preset', 'balanced')
    if preset not in ('fast', 'balanced', 'all'): raise ValueError('Неизвестный набор Nuclei')
    result['nuclei_preset'] = preset
    result['nuclei_severities'] = _list(data.get('nuclei_severities', SEVERITIES))
    if not result['nuclei_severities'] or any(s not in SEVERITIES for s in result['nuclei_severities']): raise ValueError('Некорректные уровни Nuclei')
    result['nuclei_ids'] = _list(data.get('nuclei_ids', []))
    if len(result['nuclei_ids']) > 100 or any(not re.fullmatch(r'[\w.-]+', x) for x in result['nuclei_ids']): raise ValueError('Некорректные ID шаблонов')
    raw_headers = data.get('headers', {})
    if isinstance(raw_headers, str):
        lines = [line for line in raw_headers.splitlines() if line.strip()]
        if any(':' not in line for line in lines): raise ValueError('Заголовок: Имя: значение')
        raw_headers = dict(line.split(':', 1) for line in lines)
    if not isinstance(raw_headers, dict) or len(raw_headers) > 30: raise ValueError('Некорректные HTTP-заголовки')
    headers = {}
    for key, value in raw_headers.items():
        key, value = str(key).strip(), str(value).strip()
        if not re.fullmatch(r'[A-Za-z0-9-]+', key) or any(ord(c)<32 or ord(c)==127 for c in value): raise ValueError('Некорректный HTTP-заголовок')
        if key.lower() in ('host','content-length','transfer-encoding','connection','proxy-authorization','proxy-connection'): raise ValueError('Служебный заголовок не поддерживается: '+key)
        headers[key] = value
    if sum(len(k)+len(v) for k,v in headers.items()) > 12000: raise ValueError('Заголовки слишком длинные')
    result['headers'] = headers
    result['stage_budgets'] = {}
    budgets = data.get('stage_budgets', {})
    if not isinstance(budgets, dict): raise ValueError('Некорректный бюджет этапа')
    for tool, value in budgets.items():
        try: value = int(value)
        except (ValueError, TypeError): raise ValueError('Некорректный бюджет этапа') from None
        if tool not in TOOLS or not 15 <= value <= 7200: raise ValueError('Некорректный бюджет этапа')
        result['stage_budgets'][tool] = value
    return result

def public_config(config):
    result = dict(config)
    result['headers'] = {k: '[скрыто]' for k in config.get('headers', {})}
    return result

def atomic_json(path, value):
    path = Path(path)
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
    temp.replace(path)

def finding(tool, title, url, evidence, severity='info', confidence='candidate', **details):
    identity = '|'.join((tool, details.get('template_id',''), title, url))
    return {'id': hashlib.sha256(identity.encode()).hexdigest()[:16], 'tool': tool,
            'title': title, 'url': url, 'evidence': str(evidence)[:4000],
            'severity': severity if severity in SEVERITIES else 'info', 'confidence': confidence, 'at': time.time(), **details}

ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
def plain(value): return ANSI.sub('', str(value))
