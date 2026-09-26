import hashlib
import ipaddress
import json
import re
import time
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

VERSION = '2.0.0'
TOOLS = ('recon', 'subfinder', 'censys', 'dns', 'ports', 'webprobe', 'gau', 'katana', 'discovery', 'cariddi', 'finalrecon', 'snallygaster', 'arjun', 'nuclei', 'dast', 'tls', 'dalfox', 'ghauri', 'auth', 'verify')
PROFILES = {
    'quick': ('recon', 'dns', 'webprobe', 'nuclei', 'tls', 'verify'),
    'recon': ('recon', 'subfinder', 'censys', 'dns', 'ports', 'webprobe', 'gau', 'katana', 'discovery', 'cariddi', 'finalrecon'),
    'audit': TOOLS,
    'custom': TOOLS,
}
LABELS = {'recon': 'HTTP · TLS · Cookies', 'subfinder': 'Пассивный поиск поддоменов',
          'dns': 'DNS · A/AAAA/MX/NS/TXT/CAA', 'ports': 'TCP-сервисы', 'webprobe': 'Живые сайты · технологии · TLS',
          'gau': 'Архивные URL', 'katana': 'Обход сайта · JS · формы', 'discovery': 'Пути · robots · sitemap · API',
          'cariddi': 'JS · секреты · endpoints', 'finalrecon': 'DNS · заголовки · сертификат',
          'snallygaster': 'Открытые служебные файлы', 'arjun': 'Скрытые параметры',
          'nuclei': 'CVE · HTTP / TCP / DNS / JavaScript', 'dalfox': 'XSS', 'ghauri': 'SQL injection',
          'dast': 'Nuclei DAST · параметры и тела запросов', 'tls': 'Nuclei SSL / TLS',
          'censys': 'Censys · пассивная инвентаризация', 'auth': 'JWT · CSRF · сравнение ролей',
          'verify': 'Повторная проверка совпадений'}
BUILTIN_TOOLS = ('recon', 'dns', 'ports', 'webprobe', 'discovery', 'censys', 'auth', 'verify')
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

def safe_join(base, reference):
    """Treat extracted HTML/JS/robots strings as untrusted URL candidates."""
    if not isinstance(reference, str): return None
    try: return canonical_url(urljoin(base, reference))
    except (ValueError, UnicodeError): return None

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
    result['agent_mode'] = data.get('agent_mode', 'auto')
    if result['agent_mode'] not in ('auto','off','fixed'): raise ValueError('Неизвестный режим агентов')
    for key, default, low, high in (('agents',2,1,4),('verify_limit',30,1,200),('censys_pages',1,1,10)):
        try: result[key] = int(data.get(key,default))
        except (TypeError,ValueError): raise ValueError(key+': ожидается число') from None
        if not low <= result[key] <= high: raise ValueError(key+f': допустимо {low}–{high}')
    for key in ('intrusive','include_weak','extended_protocols','oast_enabled','scan_forms'):
        result[key] = data.get(key,False) is True
    from .catalog import CATEGORIES
    result['categories'] = _list(data.get('categories',list(CATEGORIES)))
    if not result['categories'] or any(k not in CATEGORIES for k in result['categories']): raise ValueError('Некорректные категории')
    for key in ('censys_token','oast_token'):
        value = str(data.get(key,''))
        if len(value)>4096 or any(ord(c)<33 for c in value): raise ValueError('Некорректный '+key)
        result[key] = value
    result['censys_org'] = str(data.get('censys_org','')).strip()
    if result['censys_org'] and not re.fullmatch(r'[a-fA-F0-9-]{36}',result['censys_org']): raise ValueError('Censys organization: UUID')
    result['oast_server'] = str(data.get('oast_server','')).strip()
    if result['oast_server']:
        u=urlsplit(canonical_url(result['oast_server']))
        if u.scheme!='https' or u.path not in ('','/') or u.query: raise ValueError('OAST: HTTPS origin собственного Interactsh')
        result['oast_server']=urlunsplit((u.scheme,u.netloc,'','',''))
    if result['oast_enabled'] and not result['oast_server']: raise ValueError('Укажите Interactsh server для OAST')
    scope=Scope(target,targets,result['include_subdomains'],ports,result['exclude_paths'])
    requests=data.get('requests',[])
    if isinstance(requests,str):
        try: requests=json.loads(requests) if requests.strip() else []
        except ValueError: raise ValueError('Запросы: ожидается JSON-массив') from None
    if not isinstance(requests,list) or len(requests)>100: raise ValueError('Допустимо до 100 импортированных запросов')
    result['requests']=[]
    for request in requests:
        if not isinstance(request,dict): raise ValueError('Некорректный запрос')
        method=str(request.get('method','GET')).upper()
        if method not in ('GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'): raise ValueError('Неподдерживаемый метод')
        body=str(request.get('body',''))
        if len(body)>20000: raise ValueError('Тело запроса: максимум 20000 символов')
        result['requests'].append({'method':method,'url':scope.require(request.get('url','')),
                                  'headers':parse_headers(request.get('headers',{})), 'body':body})
    result['auth_headers_b']=parse_headers(data.get('auth_headers_b',{}))
    result['auth_urls']=[scope.require(u) for u in _list(data.get('auth_urls',[]))]
    if len(result['auth_urls'])>30: raise ValueError('До 30 URL для сравнения ролей')
    result['auth_marker']=str(data.get('auth_marker',''))[:500]
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
    result['auth_headers_b']={k:'[скрыто]' for k in config.get('auth_headers_b',{})}
    for key in ('censys_token','oast_token','auth_marker'):
        result[key]='[скрыто]' if config.get(key) else ''
    result['requests']=[{'method':r['method'],'url':r['url'],'headers':{k:'[скрыто]' for k in r.get('headers',{})},
                        'body':'[скрыто]' if r.get('body') else ''} for r in config.get('requests',[])]
    return result

def parse_headers(raw):
    if isinstance(raw,str):
        lines=[s for s in raw.splitlines() if s.strip()]
        if any(':' not in s for s in lines): raise ValueError('Заголовок: Имя: значение')
        raw=dict(s.split(':',1) for s in lines)
    if not isinstance(raw,dict) or len(raw)>30: raise ValueError('Некорректные заголовки')
    result={}
    for key,value in raw.items():
        key,value=str(key).strip(),str(value).strip()
        if not re.fullmatch(r'[A-Za-z0-9-]+',key) or any(ord(c)<32 or ord(c)==127 for c in value): raise ValueError('Некорректный заголовок')
        if key.lower() in ('host','content-length','transfer-encoding','connection','proxy-authorization','proxy-connection'): raise ValueError('Служебный заголовок: '+key)
        result[key]=value
    if sum(len(k)+len(v) for k,v in result.items())>12000: raise ValueError('Заголовки слишком длинные')
    return result

def secret_values(config):
    values=list(config.get('headers',{}).values())+list(config.get('auth_headers_b',{}).values())
    values += [config.get(k,'') for k in ('censys_token','oast_token','auth_marker')]
    def leaves(value):
        if isinstance(value,dict):return [s for v in value.values() for s in leaves(v)]
        if isinstance(value,list):return [s for v in value for s in leaves(v)]
        return [value] if isinstance(value,str) else []
    from urllib.parse import parse_qsl
    for row in config.get('requests',[]):
        body=row.get('body','');values += list(row.get('headers',{}).values())+[body]
        try:values += leaves(json.loads(body))
        except ValueError:values += [v for k,v in parse_qsl(body)]
    values += [v[7:] for v in list(values) if isinstance(v,str) and v.startswith('Bearer ')]
    return sorted({str(x) for x in values if len(str(x))>=4},key=len,reverse=True)

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
