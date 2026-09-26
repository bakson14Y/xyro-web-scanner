"""Context-dependent auth checks: candidates with controls, never inferred IDOR."""
import base64
import hashlib
import hmac
import json
import re
from . import builtin
from .model import finding


def decode(segment):
    return json.loads(base64.urlsafe_b64decode(segment+'='*((-len(segment))%4)))


def jwt_audit(scan):
    for value in scan.config.get('headers',{}).values():
        token=value.removeprefix('Bearer ').strip()
        parts=token.split('.')
        if len(parts)!=3 or len(token)>16000: continue
        try: header,payload=decode(parts[0]),decode(parts[1])
        except (ValueError,UnicodeError): continue
        if not isinstance(header,dict) or not isinstance(payload,dict):continue
        algorithm=header.get('alg','')
        digest=hashlib.sha256(token.encode()).hexdigest()[:20]
        if str(algorithm).lower()=='none' or not parts[2]:
            scan.add(finding('auth','JWT без криптографической подписи',scan.scope.target,
                'alg='+str(algorithm)+'; token SHA256='+digest,'medium','observed',categories=['jwt'],
                remediation='Проверить, принимает ли сервер неподписанный токен; требовать разрешённый алгоритм и подпись.'))
        if algorithm in ('HS256','HS384','HS512'):
            try: signature=base64.urlsafe_b64decode(parts[2]+'='*((-len(parts[2]))%4))
            except ValueError: continue
            algorithm_fn={'HS256':hashlib.sha256,'HS384':hashlib.sha384,'HS512':hashlib.sha512}[algorithm]
            for key in ('secret','password','123456','changeme','jwt_secret','your-256-bit-secret','test','admin','development'):
                scan.check()
                computed=hmac.new(key.encode(),'.'.join(parts[:2]).encode(),algorithm_fn).digest()
                if hmac.compare_digest(signature,computed):
                    scan.add(finding('auth','JWT подписан слабым известным секретом',scan.scope.target,
                        'Подпись проверена локально; token SHA256='+digest+'; key SHA256='+hashlib.sha256(key.encode()).hexdigest()[:20],
                        'high','cryptographic-match',categories=['jwt'],verification='reproduced',
                        remediation='Заменить ключ случайным секретом достаточной длины и отозвать выпущенные токены.'))
                    break


def run(scan):
    jwt_audit(scan)
    urls=scan.config.get('auth_urls',[])
    role_b=scan.config.get('auth_headers_b',{})
    marker=scan.config.get('auth_marker','')
    if not urls or not scan.config.get('headers') or not role_b or not marker:
        scan.progress(detail='JWT проверен локально. Для IDOR нужны URL, две роли и маркер защищённых данных',auth_context='required')
        return
    for url in urls:
        scan.check()
        # Explicit headers avoid inheriting the primary account for controls.
        def fetch(headers):
            scan.check()
            scan.pace()
            return builtin.request(scan.scope,url,timeout=10,headers=headers)
        owner=fetch(scan.config['headers'])
        anonymous=fetch({})
        other=fetch(role_b)
        repeated=fetch(role_b)
        if owner[0]==200 and marker in owner[2] and marker not in anonymous[2] and all(r[0]==200 and marker in r[2] for r in (other,repeated)):
            scan.add(finding('auth','Роль B получила указанные защищённые данные',url,
                'Роль A: 200 и маркер; без сессии: маркера нет; роль B: маркер присутствует в двух ответах. '
                'Проверьте, должна ли роль B иметь доступ.','high','candidate',categories=['idor'],verification='reproduced',
                remediation='Проверять права текущего пользователя на каждый объект на стороне сервера.'))
        scan.asset('auth-comparison',url,url=url,owner_status=owner[0],anonymous_status=anonymous[0],role_b_status=other[0],source='auth')
