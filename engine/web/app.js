"use strict";
const $ = id => document.getElementById(id);
const token = location.hash.slice(1) || sessionStorage.getItem("xyro-session") || "";
if (token) sessionStorage.setItem("xyro-session", token);
history.replaceState(null, "", "/");
let current = null, report = null, busy = false;
const states = {queued:"В очереди",running:"Выполняется",completed:"Завершено",partial:"Частично",error:"Ошибка",cancelled:"Остановлено",missing:"Нет модуля",timeout:"Лимит времени",interrupted:"Прервано"};
async function api(path, body) {
  const response = await fetch(path, {method:body===undefined?"GET":"POST",headers:{Authorization:`Bearer ${token}`,"Content-Type":"application/json"},body:body===undefined?undefined:JSON.stringify(body)});
  if(!response.ok){let error;try{error=(await response.json()).error;}catch{error=`HTTP ${response.status}`;}throw Error(error);}
  return response.json();
}
function fail(e){$("error").textContent=e.message||String(e);$("error").hidden=false;}
function el(tag,text,cls){const node=document.createElement(tag);if(text!==undefined)node.textContent=text;if(cls)node.className=cls;return node;}
function details(title,text){$("detail-title").textContent=title;$("detail-body").textContent=text;$("detail").showModal();}
function switchTab(id){document.querySelectorAll(".tab").forEach(t=>t.hidden=t.id!==id);document.querySelectorAll(".nav").forEach(t=>t.classList.toggle("active",t.dataset.tab===id));if(id==="history")loadHistory().catch(fail);}
document.querySelectorAll(".nav").forEach(n=>n.addEventListener("click",()=>switchTab(n.dataset.tab)));
$("close-detail").onclick=()=>$("detail").close();
$("profile").onchange=()=>$("profile-hint").textContent=$("profile").value==="audit"?"Активные тесты: XSS, SQLi, поиск параметров и служебных файлов. Запускайте в согласованное окно проверки.":"Обход страниц и поиск конфигурационных проблем.";
$("scan-form").onsubmit=async event=>{
  event.preventDefault();$("error").hidden=true;$("start").disabled=true;
  try{const data={target:$("target").value,profile:$("profile").value};["rps","depth","max_urls","stage_timeout"].forEach(k=>data[k]=Number($(k).value));const job=await api("/api/jobs",data);current=job.id;await poll();}catch(e){fail(e);$("start").disabled=false;}
};
$("cancel").onclick=async()=>{try{await api(`/api/cancel/${current}`,{});$("cancel").disabled=true;$("job-status").textContent="ОСТАНОВКА…";}catch(e){fail(e);}};
$("export").onclick=async()=>{try{
  if(window.AndroidExport){window.AndroidExport.save(current);return;}
  const r=await fetch(`/api/export/${current}`,{headers:{Authorization:`Bearer ${token}`}});if(!r.ok)throw Error("Не удалось экспортировать отчёт");
  const url=URL.createObjectURL(await r.blob()),a=document.createElement("a");a.href=url;a.download=`XYRO-${current}.zip`;a.click();setTimeout(()=>URL.revokeObjectURL(url),10000);
}catch(e){fail(e);}};
$("severity").onchange=renderFindings;
function renderFindings(){if(!report)return;const root=$("findings");root.replaceChildren();const rows=report.findings.filter(f=>$("severity").value==="all"||f.severity===$("severity").value);
  if(!rows.length){root.append(el("p","В этом фильтре нет наблюдений. Проверяйте статус всех этапов.","empty"));return;}
  rows.forEach(f=>{const b=el("button",undefined,"finding");b.append(el("span",f.severity,"level "+f.severity));const box=el("span");box.append(el("b",f.title),el("small",`${f.url} · ${f.confidence==="observed"?"Наблюдение":"Требует проверки"}`));b.append(box,el("span",f.tool,"tool"));b.onclick=()=>details(f.title,`${f.tool} / ${f.confidence}\n${f.url}\n\n${f.evidence}`);root.append(b);});
}
function render(){const running=["running","queued"].includes(report.status);$("start").disabled=running;$("cancel").disabled=!running;$("export").disabled=running;$("job-status").textContent=(states[report.status]||report.status).toUpperCase();$("job-target").textContent=report.target;$("url-count").textContent=report.urls.length;$("finding-count").textContent=report.findings.length;$("stage-count").textContent=`${report.stages.filter(s=>s.status==="completed").length} / ${report.config.profile==="audit"?9:5}`;
  const root=$("stages");root.replaceChildren();report.stages.forEach(s=>{const row=el("div",undefined,"stage");row.append(el("span",s.tool));const b=el("button",states[s.status]||s.status,s.status);b.onclick=async()=>{try{const log=await api(`/api/log/${current}/${s.tool}`);details(s.tool,(s.error?s.error+"\n\n":"")+log.text);}catch(e){fail(e);}};row.append(b);root.append(row);});renderFindings();
}
async function poll(){if(!current||busy)return;busy=true;try{report=await api(`/api/job/${current}`);render();}catch(e){fail(e);}finally{busy=false;}}
async function loadHistory(){const root=$("history-list");root.replaceChildren();const jobs=await api("/api/jobs");if(!jobs.length)root.append(el("p","Проверок пока нет.","empty"));jobs.forEach(j=>{const b=el("button",undefined,"history-item");const box=el("span");box.append(el("strong",j.target),el("small",new Date(j.created*1000).toLocaleString("ru-RU")));b.append(box,el("small",states[j.status]||j.status));b.onclick=async()=>{current=j.id;switchTab("scan");await poll();};root.append(b);});}
async function init(){const data=await api("/api/info"),entries=Object.entries(data.tools),ready=entries.filter(([,v])=>v.ready).length;$("health").textContent=`${ready} / ${entries.length} МОДУЛЕЙ`;$("platform").textContent=data.platform.toUpperCase();const root=$("tool-list");entries.forEach(([name,v])=>{const row=el("div",undefined,"tool-item"),box=el("span");box.append(el("strong",name),el("small",data.labels[name]));row.append(box,el("span",v.ready?"ГОТОВ":"НЕ УСТАНОВЛЕН",v.ready?"ready":"missing"));root.append(row);});const jobs=await api("/api/jobs");if(jobs.length){current=jobs[0].id;await poll();}}
init().catch(fail);setInterval(poll,2000);
