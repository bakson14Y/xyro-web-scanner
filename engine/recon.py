"""Deterministic recon stages shared by Android and desktop."""
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import ipaddress
import json
import re
import secrets
import socket
import ssl
import time
from urllib.parse import urljoin, urlsplit, parse_qsl
from xml.etree import ElementTree
from . import builtin
from .model import finding, host_url, origin

PATHS = '''/robots.txt /sitemap.xml /sitemap_index.xml /security.txt /.well-known/security.txt /.well-known/openid-configuration
/.well-known/assetlinks.json /.well-known/apple-app-site-association /humans.txt /manifest.json /site.webmanifest
/openapi.json /openapi.yaml /swagger.json /swagger.yaml /swagger-ui/ /api-docs /v2/api-docs /v3/api-docs /docs /redoc
/api /api/v1 /api/v2 /graphql /graphiql /rest /health /healthz /ready /readyz /status /version /info /ping
/metrics /actuator /actuator/health /actuator/info /actuator/env /actuator/metrics /actuator/mappings
/admin /administrator /login /signin /auth /oauth /oauth2 /console /dashboard /management /manager/html
/wp-json/ /wp-login.php /wp-admin/ /xmlrpc.php /wp-content/ /wp-includes/ /wp-sitemap.xml /readme.html
/server-status /server-info /phpinfo.php /info.php /debug /debug/vars /debug/pprof/ /trace /error /_profiler /
/.git/HEAD /.git/config /.svn/entries /.hg/hgrc /.env /.env.local /.env.production /.env.backup
/composer.json /composer.lock /package.json /package-lock.json /yarn.lock /Gemfile /requirements.txt /Dockerfile /docker-compose.yml
/config.json /config.yml /config.yaml /appsettings.json /web.config /config.php.bak /config.php.old
/backup.zip /backup.sql /database.sql /db.sql /dump.sql /site.zip /www.zip /backup.tar.gz
/logs/ /log/ /error.log /access.log /debug.log /storage/logs/laravel.log
/uploads/ /upload/ /files/ /static/ /assets/ /media/ /public/ /images/ /js/ /css/
/test /testing /staging /dev /old /backup /temp /tmp /beta /support /help /search /sso /register /forgot-password
/.DS_Store /crossdomain.xml /clientaccesspolicy.xml /favicon.ico /browserconfig.xml /feed /rss /rss.xml /atom.xml'''.split()
TECH = {
 'WordPress': r'wp-content/|wp-includes/|wp-json', 'Drupal': r'Drupal\.settings|drupalSettings|/sites/default/files',
 'Joomla': r'/media/system/js/|joomla', 'Next.js': r'/_next/|__NEXT_DATA__', 'Nuxt': r'/_nuxt/|__NUXT__',
 'React': r'data-reactroot|react-dom', 'Vue': r'data-v-[a-f0-9]{6,}|vue\.runtime', 'Angular': r'ng-version|ng-app',
 'SvelteKit': r'/_app/immutable/|sveltekit', 'Laravel': r'laravel_session|laravel', 'Django': r'csrftoken|__admin_media_prefix__',
 'ASP.NET': r'__VIEWSTATE|ASP\.NET|\.AspNetCore', 'Express': r'x-powered-by: express', 'PHP': r'x-powered-by: php|PHPSESSID',
 'nginx': r'server: nginx', 'Apache': r'server: apache', 'IIS': r'server: microsoft-iis',
 'Cloudflare': r'server: cloudflare|cf-ray:', 'Varnish': r'via:.*varnish|x-varnish:',
 'Shopify': r'cdn\.shopify\.com|myshopify\.com', 'Magento': r'Mage\.Cookies|Magento_|/static/version',
 'WooCommerce': r'woocommerce|wc-ajax', 'Spring Boot': r'Whitelabel Error Page|X-Application-Context',
 'Jenkins': r'x-jenkins:|jenkins\.js', 'Grafana': r'grafanaBootData|grafana-app', 'Kibana': r'kbn-name:|kbn-injected-metadata',
 'Swagger UI': r'swagger-ui|SwaggerUIBundle', 'Keycloak': r'keycloak|kc-form-login',
 'GitLab': r'gon\.gitlab|gitlab-', 'Confluence': r'confluence-base-url|ajs-version-number',
}


def _parallel(run, values, fn):
    with ThreadPoolExecutor(max_workers=run.config['concurrency']) as pool:
        futures = [pool.submit(fn, value) for value in values]
        for future in as_completed(futures):
            run.check()
            future.result()


def dns_inventory(run):
    import dns.resolver
    try: resolver=dns.resolver.Resolver()
    except dns.resolver.NoResolverConfiguration:
        resolver=dns.resolver.Resolver(configure=False);resolver.nameservers=['1.1.1.1','8.8.8.8']
    resolver.timeout=2;resolver.lifetime=4
    def inspect(host):
        run.check()
        try:
            address=ipaddress.ip_address(host)
            run.asset('dns',host,host=host,record='AAAA' if address.version==6 else 'A',values=[host]);return
        except ValueError:pass
        for kind in ('A','AAAA','CNAME','MX','NS','TXT','CAA'):
            run.check()
            try:
                answers=resolver.resolve(host,kind,search=False)
                values=[a.to_text()[:1000] for a in answers]
                run.asset('dns',host+'|'+kind,host=host,record=kind,values=values)
            except dns.resolver.NXDOMAIN:break
            except (dns.resolver.NoAnswer,dns.resolver.NoNameservers,dns.exception.Timeout):continue
    _parallel(run,run.active_hosts(),inspect)


def port_inventory(run):
    pairs=[]
    for host in run.active_hosts():
        ports=run.config['ports'] or sorted({p for _,h,p in run.scope.origins if h==host} or {run.scope.origin[2]})
        pairs.extend((host,p) for p in ports)
    def probe(pair):
        run.check();host,port=pair
        try:
            with socket.create_connection((host,port),timeout=2):
                run.asset('service',host+':'+str(port),host=host,port=port,transport='tcp',status='open',source='connect')
        except OSError:pass
    _parallel(run,pairs,probe)


def web_probe(run):
    urls=list(run.scope.targets)
    for host in run.active_hosts():
        for scheme,_,port in run.scope.origins:
            urls.append(host_url(scheme,host,port))
        for port in run.config['ports']:
            schemes=('https','http') if port in (443,8443,9443) else ('http','https')
            urls.extend(host_url(s,host,port) for s in schemes)
    urls=list(dict.fromkeys(u for u in urls if run.scope.contains(u)))
    def probe(url):
        run.check()
        try: status,pairs,body,final=run.request(url,timeout=5)
        except (OSError,ValueError) as exc:
            run.log('webprobe',url+' '+str(exc));return
        headers={k.lower():v for k,v in pairs}
        title=re.search(r'<title[^>]*>(.*?)</title',body,re.I|re.S)
        title=re.sub(r'\s+',' ',title.group(1)).strip()[:180] if title else ''
        sample='\n'.join(k+': '+v for k,v in pairs)+'\n'+body[:250000]
        tech=[name for name,pattern in TECH.items() if re.search(pattern,sample,re.I)]
        run.add_url(final,source='webprobe')
        run.asset('web',final,url=final,host=urlsplit(final).hostname,status=status,title=title,
                  technologies=tech,server=headers.get('server',''),content_type=headers.get('content-type',''),size=len(body))
        parser=builtin.Links();parser.feed(body)
        from .forms import capture
        capture(run,final,body)
        for path in parser.urls:run.add_link(final,path,source='html')
        for path in re.findall(r'''["']((?:https?://|/)[^\s"'<>]{2,300})["']''',body):run.add_link(final,path,source='js-inline')
        for name in re.findall(r'<(?:input|select|textarea)\b[^>]*\bname=["\']([^"\']+)',body,re.I):
            run.asset('parameter',final+'|'+name,url=final,name=name,source='html-form')
        if urlsplit(final).scheme=='https': tls_probe(run,final)
        try:
            _,cors_pairs,_,_=run.request(final,timeout=5,headers={'Origin':'https://xyro.invalid'})
            cors={k.lower():v for k,v in cors_pairs}
            if cors.get('access-control-allow-origin')=='https://xyro.invalid':
                credentials=cors.get('access-control-allow-credentials','').lower()=='true'
                run.add(finding('webprobe','CORS отражает произвольный Origin',final,
                    'Origin отражён'+('; разрешены credentials' if credentials else ''),
                    'medium' if credentials else 'low',remediation='Проверьте allowlist доверенных Origin и необходимость credentials.'))
        except (OSError,ValueError):pass
    _parallel(run,urls,probe)


def tls_probe(run,url):
    import certifi
    u=urlsplit(url)
    try:
        context=ssl.create_default_context(cafile=certifi.where())
        with socket.create_connection((u.hostname,u.port or 443),timeout=5) as raw:
            with context.wrap_socket(raw,server_hostname=u.hostname) as secure:
                cert=secure.getpeercert()
                expiry=ssl.cert_time_to_seconds(cert['notAfter'])
                days=int((expiry-time.time())/86400)
                sans=[name for kind,name in cert.get('subjectAltName',()) if kind=='DNS']
                run.asset('tls',url,url=url,protocol=secure.version(),cipher=secure.cipher()[0],days_left=days,
                          expires=cert['notAfter'],issuer=str(cert.get('issuer',())),sans=sans[:100])
                for name in sans:
                    if not name.startswith('*.'):run.add_host(name,'certificate')
                if days<30:run.add(finding('webprobe','Сертификат скоро истекает',url,f'Осталось дней: {days}','low','observed'))
    except (OSError,ValueError,KeyError) as exc:run.log('webprobe','TLS: '+str(exc))


def _fingerprint(body,path):
    body=body.replace(path,'<path>')
    return re.sub(r'\s+',' ',re.sub(r'[0-9a-f]{16,}|\d{4,}','#',body)).strip()[:30000]


def discovery(run):
    seeds=list(dict.fromkeys(host_url(*origin(u)) for u in run.urls))
    for base in seeds[:run.config['max_hosts']]:
        run.check()
        fake='/xyro-not-found-'+secrets.token_hex(10)
        try:
            bs,bh,bb,_=run.request(urljoin(base,fake),timeout=5)
            baseline=(bs,_fingerprint(bb,fake))
        except (OSError,ValueError):baseline=None
        paths=list(dict.fromkeys(['/robots.txt','/sitemap.xml']+PATHS+run.config['custom_paths']))
        def inspect(path):
            run.check();url=urljoin(base,path)
            if not run.scope.contains(url):return
            try:status,headers,body,final=run.request(url,timeout=5)
            except (OSError,ValueError):return
            if status in (404,410) or status>=500:return
            if baseline and status==baseline[0] and _fingerprint(body,path)==baseline[1]:return
            if status not in (200,201,204,301,302,307,308,401,403):return
            run.add_url(final,source='discovery')
            run.asset('path',final,url=final,status=status,size=len(body),source='discovery')
            content_type=dict((k.lower(),v) for k,v in headers).get('content-type','')
            if 'html' in content_type:
                from .forms import capture
                capture(run,final,body)
            if path=='/robots.txt':
                for value in re.findall(r'(?im)^(?:allow|disallow|sitemap):\s*(\S+)',body):run.add_link(base,value,source='robots')
            if 'xml' in content_type or path.endswith('.xml'):
                try:
                    doc=ElementTree.fromstring(body)
                    for node in doc.iter():
                        if node.tag.rsplit('}',1)[-1]=='loc' and node.text:run.add_url(node.text.strip(),source='sitemap')
                except ElementTree.ParseError:pass
            if path.endswith('.json') and ('swagger' in body[:1000] or 'openapi' in body[:1000]):
                try:
                    document=json.loads(body)
                    for endpoint in list(document.get('paths',{}))[:1000]:
                        if isinstance(endpoint,str):run.add_link(base,endpoint,source='openapi')
                    run.add(finding('discovery','Опубликовано описание API',final,'OpenAPI/Swagger содержит маршруты API',confidence='observed'))
                except (ValueError,AttributeError):pass
        _parallel(run,paths,inspect)
    # Inspect a bounded set of discovered scripts without evaluating JavaScript.
    scripts=[u for u in run.urls if urlsplit(u).path.endswith('.js')][:min(100,run.config['max_urls'])]
    for url in scripts:
        run.check()
        try:_,_,body,final=run.request(url,timeout=5)
        except (OSError,ValueError):continue
        for endpoint in re.findall(r'''["'`]((?:https?://|/)[^\s"'`<>]{2,250})["'`]''',body):
            run.add_link(final,endpoint,source='javascript')

STAGES={'dns':dns_inventory,'ports':port_inventory,'webprobe':web_probe,'discovery':discovery}
