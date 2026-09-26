import csv
import html
import io
import json
from collections import Counter
from .model import VERSION, SEVERITIES

def render_html(report):
    e=lambda value:html.escape(str(value))
    counts=Counter(f.get('severity','info') for f in report['findings'])
    rows=''.join('<tr>'+''.join('<td>'+e(f.get(k,''))+'</td>' for k in ('severity','tool','title','url','confidence','verification','evidence'))+'</tr>' for f in sorted(report['findings'],key=lambda f:SEVERITIES.index(f.get('severity','info'))))
    stages=''.join('<tr>'+''.join('<td>'+e(s.get(k,''))+'</td>' for k in ('tool','status','error'))+'</tr>' for s in report['stages'])
    coverage=''.join('<tr><td>'+e(c['label'])+'</td><td>'+str(c['selected'])+' / '+str(c['catalog'])+'</td><td>'+e('; '.join(k+': '+str(v) for k,v in c.get('reasons',{}).items()))+'</td></tr>' for c in report.get('coverage',[]))
    tasks=''.join('<tr><td>'+e(t['id'])+'</td><td>'+e(t['tool'])+'</td><td>'+e(t['status'])+'</td><td>'+e(t.get('error',t.get('detail','')))+'</td></tr>' for t in report.get('tasks',[]))
    assets=''.join('<tr><td>'+e(a['kind'])+'</td><td>'+e(a['key'])+'</td><td>'+e(json.dumps({k:v for k,v in a.items() if k not in ('kind','key')},ensure_ascii=False))+'</td></tr>' for a in report.get('assets',[]))
    return ("<!doctype html><html lang='ru'><meta charset='utf-8'><meta name='viewport' content='width=device-width'><title>XYRO · Отчёт</title>"
      "<style>body{font:15px/1.6 system-ui;margin:40px;color:#172a24;max-width:1600px}h1{font-size:40px}h2{margin-top:38px}table{border-collapse:collapse;width:100%;font-size:12px}td,th{border:1px solid #cddbd6;padding:10px;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#eef6f2}p{max-width:1000px}.stats{display:flex;gap:20px;flex-wrap:wrap}.stat{padding:12px 20px;border:1px solid #cddbd6;border-radius:10px}small{color:#62766c}@media print{body{margin:15px}tr{break-inside:avoid}}</style>"
      '<h1>XYRO / '+VERSION+'</h1><p>'+e(report['target'])+'</p><p>Состояние: '+e(report['status'])+'</p>'
      '<div class="stats">'+''.join('<div class="stat">'+e(s)+': <b>'+str(counts[s])+'</b></div>' for s in SEVERITIES)+'</div>'
      '<p>Совпадения шаблонов и кандидаты требуют проверки. Таймауты означают частичное покрытие. Отсутствие находок не доказывает безопасность сайта.</p>'
      '<h2>Этапы</h2><table><tr><th>Модуль<th>Состояние<th>Подробности</tr>'+stages+'</table>'
      '<h2>Покрытие</h2><p>Выбрано / каталог. Выбор шаблона не означает его применимость к каждому запросу или отсутствие уязвимостей.</p><table><tr><th>Категория<th>Шаблоны<th>Причины пропуска</tr>'+coverage+'</table>'
      '<h2>Задачи агентов</h2><table><tr><th>ID<th>Модуль<th>Состояние<th>Подробности</tr>'+tasks+'</table>'
      '<h2>Находки</h2><table><tr><th>Уровень<th>Модуль<th>Находка<th>URL<th>Доказательство<th>Перепроверка<th>Данные</tr>'+rows+'</table>'
      '<h2>Активы</h2><table><tr><th>Тип<th>Адрес / ключ<th>Данные</tr>'+assets+'</table></html>')

def csv_report(report):
    stream=io.StringIO(newline='');writer=csv.writer(stream)
    columns=('severity','tool','title','url','confidence','verification','template_id','evidence','remediation')
    writer.writerow(columns)
    for item in report['findings']:
        row=[]
        for key in columns:
            value=str(item.get(key,''))
            row.append("'"+value if value.startswith(('=','+','-','@','\t','\r')) else value)
        writer.writerow(row)
    return '\ufeff'+stream.getvalue()

def sarif_report(report):
    rules={};results=[]
    for item in report['findings']:
        rule=item.get('template_id') or item['tool']+'/'+item['id']
        rules.setdefault(rule,{'id':rule,'name':item['title'],'shortDescription':{'text':item['title']},
                              'help':{'text':item.get('remediation','Проверьте доказательства вручную.')}})
        results.append({'ruleId':rule,'level':'error' if item['severity'] in ('critical','high') else 'warning' if item['severity']=='medium' else 'note',
                        'message':{'text':item['title']+'\n'+item['evidence']},
                        'locations':[{'physicalLocation':{'artifactLocation':{'uri':item['url']}}}],
                        'properties':{'severity':item['severity'],'confidence':item['confidence'],'verification':item.get('verification','not_run'),'categories':item.get('categories',[]),'tool':item['tool']}})
    return {'$schema':'https://json.schemastore.org/sarif-2.1.0.json','version':'2.1.0',
            'runs':[{'tool':{'driver':{'name':'XYRO','version':VERSION,'rules':list(rules.values())}},'results':results,
                     'invocations':[{'executionSuccessful':report['status']=='completed'}]}]}
