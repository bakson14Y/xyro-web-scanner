"""Parse forms as data; never execute scripts or invent authenticated requests."""
from html.parser import HTMLParser
import re
from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl
from .model import safe_join, finding

class Forms(HTMLParser):
    def __init__(self):
        super().__init__();self.forms=[];self.current=None

    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if tag=='form':
            self.current={'action':a.get('action',''),'method':a.get('method','GET').upper(),
                          'enctype':a.get('enctype','application/x-www-form-urlencoded'),'fields':[]}
            self.forms.append(self.current)
        elif self.current is not None and tag in ('input','select','textarea') and a.get('name') and 'disabled' not in a:
            kind=a.get('type','text').lower()
            if kind not in ('submit','button','reset','file','password','checkbox','radio'):
                self.current['fields'].append((a['name'],a.get('value','xyro-test')))

    def handle_endtag(self,tag):
        if tag=='form':self.current=None

def capture(scan,url,body):
    parser=Forms();parser.feed(body[:500000])
    for index,form in enumerate(parser.forms[:30]):
        action=safe_join(url,form['action'])
        if not action or not scan.scope.contains(action):continue
        method=form['method'];fields=form['fields'][:100]
        names=[k for k,v in fields]
        csrf=any(re.search(r'csrf|xsrf|authenticity|requestverification',k,re.I) for k in names)
        scan.asset('form',url+'|'+str(index),url=url,action=action,method=method,fields=names,csrf_field=csrf,source='html')
        if method=='POST' and not csrf and 'csrf' in scan.config.get('categories',['csrf']):
            scan.add(finding('auth','У формы не обнаружено явного CSRF-поля',action,
                'Наблюдение по HTML. Защита может опираться на Origin, SameSite или заголовок; уязвимость не подтверждена.',
                'info','observed',categories=['csrf'],verification='context_required'))
        if not scan.config.get('scan_forms') or method not in ('GET','POST') or not fields:continue
        if method=='POST' and form['enctype']!='application/x-www-form-urlencoded':continue
        if method=='GET':
            p=urlsplit(action)
            action=urlunsplit((p.scheme,p.netloc,p.path,urlencode(parse_qsl(p.query,keep_blank_values=True)+fields),''))
        scan.capture_request({'url':action,'method':method,'headers':{'Content-Type':'application/x-www-form-urlencoded'} if method=='POST' else {},
                              'body':urlencode(fields) if method=='POST' else ''})
        scan.add_url(action,source='form')
