"""Deterministic template classification. Catalogue presence is not coverage."""
import re

CATEGORIES = {
    'sqli': 'SQL injection', 'ssti': 'SSTI / CSTI', 'rce': 'Command injection / RCE',
    'deserialization': 'Десериализация', 'xxe': 'XXE', 'jwt': 'JWT',
    'oauth': 'OAuth / OpenID', 'cors': 'CORS', 'idor': 'IDOR / контроль доступа',
    'csrf': 'CSRF', 'rate_limit': 'Rate limiting', 'smuggling': 'HTTP smuggling',
    'ssrf': 'SSRF', 'lfi': 'LFI / Path traversal', 'rfi': 'RFI',
    'redirect': 'Open redirect', 'takeover': 'Subdomain takeover',
    'prototype': 'Prototype pollution', 'crlf': 'CRLF', 'xss': 'XSS',
    'ssl': 'SSL / TLS', 'cve': 'CVE', 'exposure': 'Экспозиции / конфигурация',
}
ALIASES = {
    'sqli': ('sqli','sql-injection'), 'ssti': ('ssti','csti','template-injection'),
    'rce': ('rce','cmdi','command-injection'), 'deserialization': ('deserialization','deserialize','ysoserial'),
    'xxe': ('xxe',), 'jwt': ('jwt','json-web-token'), 'oauth': ('oauth','openid','oidc'),
    'cors': ('cors',), 'idor': ('idor','bola','broken-access'), 'csrf': ('csrf',),
    'rate_limit': ('rate-limit','ratelimit'), 'smuggling': ('smuggling','desync'),
    'ssrf': ('ssrf',), 'lfi': ('lfi','traversal'), 'rfi': ('rfi',),
    'redirect': ('redirect',), 'takeover': ('takeover',), 'prototype': ('prototype',),
    'crlf': ('crlf',), 'xss': ('xss',), 'ssl': ('heartbleed','tls','ssl'),
}
PROTOCOLS = ('http','ssl','dns','tcp','network','javascript','headless','code','file','websocket','whois')
SUPPORTED = {'http','ssl','dns','tcp','javascript'}


def classify(path, doc, text, ignored_files=(), ignored_tags=()):
    info = doc.get('info', {})
    tags = info.get('tags', [])
    if isinstance(tags, str): tags = [s.strip() for s in tags.split(',')]
    tags = [str(t).lower() for t in tags]
    probe = (' '.join([path, str(info.get('name','')), *tags])).lower()
    categories = [key for key, terms in ALIASES.items() if any(t in probe for t in terms)]
    if '/cves/' in path or str(doc['id']).upper().startswith('CVE-'): categories.append('cve')
    if not categories: categories.append('exposure')
    protocols = [('tcp' if p == 'network' else p) for p in PROTOCOLS if p in doc]
    mode = 'dast' if path.startswith('dast/') or re.search(r'^\s+fuzzing:', text, re.M) else 'tls' if protocols == ['ssl'] else 'nuclei'
    unsupported = sorted(set(protocols) - SUPPORTED)
    reason = ('Требуется браузер Chromium' if 'headless' in unsupported else
              'Протокол не поддержан мобильным runtime: '+','.join(unsupported) if unsupported else
              'Шаблон не имеет поддерживаемого протокола' if not protocols else
              'Self-contained: отдельная цель не определяется' if doc.get('self-contained') else
              'Локальная / разрушительная проверка' if {'dos','local'}.intersection(tags) else
              'Нет подписи upstream' if '# digest:' not in text else '')
    group = path.split('/')[1] if '/' in path else path
    return {'id': str(doc['id']), 'path': path, 'name': str(info.get('name', doc['id'])),
            'severity': str(info.get('severity','info')), 'tags': tags, 'group': group,
            'categories': sorted(set(categories)), 'protocols': protocols, 'mode': mode,
            'oast': bool(re.search(r'interactsh[-_]', text)),
            'intrusive': bool({'rce','deserialization','xxe','smuggling','rfi'}.intersection(categories) or
                              {'bruteforce','fuzz','fuzzing'}.intersection(tags)),
            'weak_matcher': path in ignored_files,
            'ignored_tags': sorted(set(tags).intersection(ignored_tags)),
            'supported': not reason, 'reason': reason,
            'year': next((p for p in path.split('/') if re.fullmatch(r'20\d{2}|19\d{2}',p)), None)}


def exclusion(row, config):
    if not row['supported']: return row['reason']
    if row['oast'] and not config.get('oast_enabled'): return 'OAST выключен'
    if row['intrusive'] and not config.get('intrusive'): return 'Активные проверки повышенного воздействия выключены'
    if row['weak_matcher'] and not config.get('include_weak'): return 'Upstream: слабый matcher; требуется явное включение'
    if any(p in ('tcp','dns','javascript') for p in row['protocols']) and not config.get('extended_protocols'):
        return 'TCP / DNS / JavaScript выключены'
    return ''
