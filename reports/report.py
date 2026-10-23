"""Console, JSON, CSV, Markdown and interactive HTML reports."""
import csv
import json
import os
from datetime import datetime


def print_summary(results, findings, summary, diff=None):
    m = summary["metrics"]
    print("\n" + "=" * 64)
    print(" Attack Surface Report: %s" % results["target"])
    print("=" * 64)
    print(" Risk: %s (score %d/100) | Hosts: %d | Open ports: %d | Web services: %d"
          % (summary["rating"], summary["score"], m.get("hosts", 0), m.get("open_ports", 0), m.get("web_services", 0)))
    print(" " + " | ".join("%s: %d" % kv for kv in summary["counts"].items()))
    for host, d in results["hosts"].items():
        ports = ", ".join("%d/%s" % (p["port"], p["service"]) for p in d["ports"]) or "none"
        print("\n  %s (%s) open: %s" % (host, d["ip"], ports))
    print("\n Top findings:")
    for f in findings[:12]:
        print("  [%-8s] %s: %s" % (f["severity"], f["host"], f["title"]))
    if diff:
        print("\n Changes since %s: %d new, %d resolved, score %+d"
              % (diff["previous_at"], len(diff["new"]), len(diff["resolved"]), diff["score_delta"]))


def save_json(results, findings, summary, diff, outdir):
    path = os.path.join(outdir, "report.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"results": results, "findings": findings, "summary": summary, "diff": diff}, fh, indent=2)
    return path


def save_csv(findings, outdir):
    path = os.path.join(outdir, "findings.csv")
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["severity", "host", "id", "title", "category", "ports", "evidence", "recommendation", "references"])
        for f in findings:
            w.writerow([f["severity"], f["host"], f["id"], f["title"], f["category"],
                        " ".join(map(str, f["ports"])), f["evidence"], f["recommendation"], f["refs"]])
    return path


def save_md(results, findings, summary, outdir):
    lines = ["# Attack Surface Report: %s" % results["target"], "",
             "Generated %s | Risk **%s** (%d/100)" % (results["scanned_at"], summary["rating"], summary["score"]), "",
             "| Severity | Host | Finding | Ports |", "|---|---|---|---|"]
    lines += ["| %s | %s | %s | %s |" % (f["severity"], f["host"], f["title"], ", ".join(map(str, f["ports"])) or "-")
              for f in findings]
    path = os.path.join(outdir, "report.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return path


TEMPLATE = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Attack Surface Report</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--text:#111827;--muted:#6b7280;--line:#e5e7eb;--accent:#2563eb}
:root[data-theme=dark]{--bg:#0f172a;--card:#1e293b;--text:#e5e7eb;--muted:#94a3b8;--line:#334155;--accent:#60a5fa}
*{box-sizing:border-box}body{margin:0;font-family:Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--text)}
.wrap{max-width:1250px;margin:0 auto;padding:1.5rem}header{display:flex;justify-content:space-between;flex-wrap:wrap;gap:1rem}
h1{margin:0 0 .25rem;font-size:1.6rem}h3{margin:.2rem 0 .6rem;font-size:1rem}.muted{color:var(--muted);font-size:.88rem}
.btn{background:var(--card);color:var(--text);border:1px solid var(--line);border-radius:8px;padding:6px 12px;cursor:pointer;font-size:.85rem}.btn:hover{border-color:var(--accent)}
.top{display:grid;grid-template-columns:230px 1fr;gap:1rem;margin:1rem 0}@media(max-width:760px){.top{grid-template-columns:1fr}}
.panel{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:1rem;margin-bottom:.8rem}
.donut{position:relative;width:170px;height:170px;margin:0 auto}.donut .mid{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}.donut .mid b{font-size:1.6rem}
.cards{display:flex;flex-wrap:wrap;gap:.6rem}.card{flex:1;min-width:95px;border:2px solid var(--line);border-radius:10px;padding:.6rem;text-align:center;cursor:pointer;background:var(--card);user-select:none}
.card b{font-size:1.5rem;display:block}.card.off{opacity:.35}.metric{flex:1;min-width:110px;text-align:center;background:var(--bg);border-radius:10px;padding:.5rem}.metric b{display:block;font-size:1.3rem}
.rating{display:inline-block;padding:3px 12px;border-radius:12px;color:#fff;font-weight:600}
.tabs{display:flex;gap:.4rem;margin:1rem 0 .5rem;flex-wrap:wrap}.tab{padding:8px 16px;border-radius:8px 8px 0 0;cursor:pointer;border:1px solid var(--line);background:var(--card)}.tab.active{border-bottom:3px solid var(--accent);font-weight:600}
.controls{display:flex;flex-wrap:wrap;gap:.6rem;align-items:center;margin-bottom:.8rem}
input[type=search],select{padding:7px 10px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--text);font-size:.9rem}input[type=search]{min-width:240px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{padding:8px 10px;text-align:left;font-size:.88rem;vertical-align:top;border-bottom:1px solid var(--line)}th{background:var(--bg);cursor:pointer;user-select:none;white-space:nowrap}th:hover{color:var(--accent)}
tr.row{cursor:pointer}tr.row:hover td{background:rgba(37,99,235,.07)}tr.detail td{background:var(--bg)}
.badge{color:#fff;padding:2px 9px;border-radius:10px;font-size:.75rem;font-weight:600}
.chip{display:inline-block;background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:1px 8px;margin:2px;font-size:.8rem}.chip.risky{border-color:#dc2626;color:#dc2626}.chip.good{border-color:#16a34a;color:#16a34a}.chip.bad{border-color:#dc2626;color:#dc2626}
.caret{display:inline-block;transition:transform .15s;margin-right:6px}.open .caret{transform:rotate(90deg)}.go{color:var(--accent);cursor:pointer;font-size:.85rem}.empty{padding:2rem;text-align:center;color:var(--muted)}
@media print{.controls,.tabs,.btn{display:none}}
</style></head><body><div class="wrap">
<header><div><h1>Attack Surface Assessment</h1><div class="muted">Target: <b id="tgt"></b> &middot; Scanned: __GENERATED__ &middot; <span id="dur"></span></div></div>
<div><button class="btn" id="theme">Toggle dark mode</button> <button class="btn" onclick="window.print()">Print</button></div></header>
<div class="top">
 <div class="panel"><div class="donut"><svg id="donut" viewBox="0 0 120 120" width="170" height="170"></svg><div class="mid"><b id="dTotal"></b><span class="muted">findings</span></div></div>
  <p style="text-align:center;margin:.6rem 0 0">Risk: <span class="rating" id="rating"></span><br><span class="muted" id="score"></span></p></div>
 <div class="panel"><div class="cards" id="metrics" style="margin-bottom:.8rem"></div><div class="muted" style="margin-bottom:.4rem">Click a severity to filter (click again to toggle)</div><div class="cards" id="cards"></div></div>
</div>
<div class="tabs"><div class="tab active" data-tab="f">Findings</div><div class="tab" data-tab="a">Assets</div><div class="tab" data-tab="d">DNS &amp; Email</div><div class="tab" data-tab="c">Changes</div></div>
<div id="pf"><div class="controls"><input type="search" id="q" placeholder="Search findings, hosts, evidence..."><select id="host"></select><select id="cat"></select>
 <button class="btn" id="expand">Expand all</button><button class="btn" id="csv">Export CSV</button><span class="muted" id="count"></span></div>
 <table><thead><tr><th data-k="sev">Severity</th><th data-k="host">Host</th><th data-k="title">Finding</th><th data-k="category">Category</th></tr></thead><tbody id="tb"></tbody></table></div>
<div id="pa" style="display:none"></div><div id="pd" style="display:none"></div><div id="pc" style="display:none"></div>
<p class="muted" style="margin-top:1.5rem">Automated results can include false positives; verify manually. Only assess systems you are authorized to test.</p></div>
<script>
const D=__DATA__,F=D.findings,S=D.summary,R=D.results,H=R.hosts,DF=D.diff,DNS=R.dns||{};
const SEV=['Critical','High','Medium','Low','Info'],COL={Critical:'#7f1d1d',High:'#dc2626',Medium:'#f59e0b',Low:'#2563eb',Info:'#6b7280'};
const st={sev:new Set(SEV),q:'',host:'all',cat:'all',key:'sev',dir:1,all:false},$=id=>document.getElementById(id);
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
$('tgt').textContent=R.target;$('dur').textContent='took '+R.duration_s+'s, profile '+R.profile;
$('rating').textContent=S.rating;$('rating').style.background={Minimal:'#16a34a',Low:'#2563eb',Medium:'#f59e0b',High:'#dc2626',Critical:'#7f1d1d'}[S.rating];
$('score').textContent='Score '+S.score+' / 100';$('dTotal').textContent=F.length;
$('metrics').innerHTML=[['Hosts',S.metrics.hosts],['Open ports',S.metrics.open_ports],['Web services',S.metrics.web_services]].map(m=>`<div class="metric"><b>${m[1]||0}</b>${m[0]}</div>`).join('');
(function(){const C=2*Math.PI*40;let off=0,h='';const t=F.length||1;SEV.forEach(s=>{const n=S.counts[s]||0;if(!n)return;const l=C*n/t;
 h+=`<circle cx="60" cy="60" r="40" fill="none" stroke="${COL[s]}" stroke-width="16" stroke-dasharray="${l} ${C-l}" stroke-dashoffset="${-off}" transform="rotate(-90 60 60)"><title>${s}: ${n}</title></circle>`;off+=l;});
 $('donut').innerHTML=h||'<circle cx="60" cy="60" r="40" fill="none" stroke="#9ca3af" stroke-width="16"/>';})();
function drawCards(){$('cards').innerHTML=SEV.map(s=>`<div class="card ${st.sev.has(s)?'':'off'}" data-s="${s}" style="border-color:${COL[s]}"><b style="color:${COL[s]}">${S.counts[s]||0}</b>${s}</div>`).join('');
 document.querySelectorAll('.card').forEach(c=>c.onclick=()=>{const s=c.dataset.s;st.sev.has(s)?st.sev.delete(s):st.sev.add(s);drawCards();render();});}
$('host').innerHTML='<option value="all">All hosts</option>'+Object.keys(H).map(h=>`<option>${esc(h)}</option>`).join('');
$('cat').innerHTML='<option value="all">All categories</option>'+[...new Set(F.map(f=>f.category))].sort().map(c=>`<option>${esc(c)}</option>`).join('');
const filtered=()=>{const q=st.q.toLowerCase();return F.filter(f=>st.sev.has(f.severity)&&(st.host==='all'||f.host===st.host)&&(st.cat==='all'||f.category===st.cat)&&(!q||(f.host+' '+f.title+' '+f.evidence+' '+f.recommendation+' '+f.id).toLowerCase().includes(q)));};
function render(){const rows=filtered();rows.sort((a,b)=>{let x,y;if(st.key==='sev'){x=SEV.indexOf(a.severity);y=SEV.indexOf(b.severity);}else{x=String(a[st.key]).toLowerCase();y=String(b[st.key]).toLowerCase();}return(x<y?-1:x>y?1:0)*st.dir;});
 $('count').textContent=rows.length+' of '+F.length+' findings';
 $('tb').innerHTML=rows.map(f=>`<tr class="row ${st.all?'open':''}"><td><span class="caret">&#9656;</span><span class="badge" style="background:${COL[f.severity]}">${f.severity}</span></td><td>${esc(f.host)}</td><td>${esc(f.title)}</td><td>${esc(f.category)}</td></tr>
 <tr class="detail" style="display:${st.all?'table-row':'none'}"><td colspan="4"><b>Rule:</b> ${esc(f.id)}${f.ports.length?' &nbsp; <b>Ports:</b> '+f.ports.join(', '):''}<br><b>Evidence:</b> ${esc(f.evidence)}<br><b>Fix:</b> ${esc(f.recommendation)}<br><b>References:</b> ${esc(f.refs)}</td></tr>`).join('')||'<tr><td colspan="4" class="empty">No findings match the current filters.</td></tr>';
 document.querySelectorAll('tr.row').forEach(r=>r.onclick=()=>{r.classList.toggle('open');const d=r.nextElementSibling;d.style.display=d.style.display==='none'?'table-row':'none';});}
const RISKY=new Set(F.filter(f=>f.id.startsWith('EXPOSED-')).flatMap(f=>f.ports));
function drawAssets(){$('pa').innerHTML=Object.entries(H).map(([h,d])=>{const n=F.filter(f=>f.host===h).length,hs=S.host_scores[h]||0;
 const chips=d.ports.length?d.ports.map(p=>`<span class="chip ${RISKY.has(p.port)?'risky':''}" title="${esc(p.banner||'')}">${p.port}/${esc(p.service)}</span>`).join(''):'<span class="muted">no open ports found</span>';
 const web=d.http.filter(x=>!x.error).map(x=>`<div class="muted">:${x.port} &rarr; HTTP ${x.status}${x.title?' &middot; "'+esc(x.title)+'"':''}</div>`).join('');
 const tech=(d.web&&d.web.tech.length)?'<div>'+d.web.tech.map(t=>`<span class="chip">${esc(t)}</span>`).join('')+'</div>':'';
 const t=d.tls?`<div class="muted">TLS: ${esc(d.tls.version||'n/a')}${d.tls.days_left!==undefined?' &middot; cert expires in '+d.tls.days_left+' days':''}${d.tls.verified===false?' &middot; <b style="color:#dc2626">certificate not trusted</b>':''}${d.tls.protocols?' &middot; supports '+Object.entries(d.tls.protocols).filter(e=>e[1]).map(e=>e[0]).join(', '):''}</div>`:'';
 return `<div class="panel"><h3>${esc(h)} <span class="muted">(${esc(d.ip)}) &middot; host risk ${hs}</span></h3><div>${chips}</div>${tech}${web}${t}<div class="go" data-h="${esc(h)}">${n} finding${n==1?'':'s'} &rarr; view</div></div>`;}).join('');
 document.querySelectorAll('.go').forEach(g=>g.onclick=()=>{$('host').value=g.dataset.h;st.host=g.dataset.h;showTab('f');render();});}
function drawDns(){const rec=DNS.records||{},em=DNS.email||{};let h='';
 if(!DNS.resolver_ok)h+='<div class="panel muted">No DNS data: target is an IP/localhost, or the resolver '+esc(DNS.resolver||'')+' was unreachable (UDP 53 may be blocked).</div>';
 else{h+='<div class="panel"><h3>DNS records</h3>'+Object.entries(rec).map(([t,v])=>`<div><b>${t}</b> ${v.length?v.map(x=>`<span class="chip">${esc(x)}</span>`).join(''):'<span class="muted">none</span>'}</div>`).join('')+'</div>';
 h+='<div class="panel"><h3>Email authentication</h3>'+(em.checked?`<div>SPF: ${em.spf?`<span class="chip ${em.spf_all=='+'||em.spf_all=='?'?'bad':'good'}">${esc(em.spf)}</span>`:'<span class="chip bad">missing</span>'}</div><div>DMARC: ${em.dmarc?`<span class="chip ${em.dmarc_policy=='none'?'bad':'good'}">${esc(em.dmarc)}</span>`:'<span class="chip bad">missing</span>'}</div>`:'<span class="muted">not checked</span>')+'</div>';
 h+='<div class="panel"><h3>Dangling CNAMEs (takeover candidates)</h3>'+((DNS.dangling||[]).length?DNS.dangling.map(x=>`<div><span class="chip bad">${esc(x.host)}</span> &rarr; ${esc(x.cname)}</div>`).join(''):'<span class="muted">none found</span>')+'</div>';}
 h+='<div class="panel"><h3>Discovered hosts &amp; sources</h3>'+Object.entries(DNS.sources||{}).map(([k,v])=>`<div>${esc(k)} ${v.map(s=>`<span class="chip">${esc(s)}</span>`).join('')}</div>`).join('')+(DNS.wildcard?'<p class="muted">Wildcard DNS detected: some wordlist hits were filtered out.</p>':'')+'</div>';
 $('pd').innerHTML=h;}
function drawChanges(){if(!DF){$('pc').innerHTML='<div class="panel muted">No earlier scan of this target found. Scan again later to see what changed (new/resolved findings, new hosts and ports).</div>';return;}
 const list=(t,a)=>`<div class="panel"><h3>${t} (${a.length})</h3>${a.length?a.map(f=>`<div><span class="badge" style="background:${COL[f.severity]}">${f.severity}</span> ${esc(f.host)} &mdash; ${esc(f.title)}</div>`).join(''):'<span class="muted">none</span>'}</div>`;
 const chips=(t,a)=>`<div>${t}: ${a.length?a.map(x=>`<span class="chip">${esc(x)}</span>`).join(''):'<span class="muted">none</span>'}</div>`;
 $('pc').innerHTML=`<div class="panel">Compared with scan from <b>${esc(DF.previous_at)}</b>: score change <b>${DF.score_delta>0?'+':''}${DF.score_delta}</b>, ${DF.unchanged} unchanged finding(s).</div>`+list('New findings',DF.new)+list('Resolved findings',DF.resolved)+'<div class="panel">'+chips('New hosts',DF.new_hosts)+chips('Removed hosts',DF.removed_hosts)+chips('Newly open ports',DF.new_ports)+chips('Closed ports',DF.closed_ports)+'</div>';}
function showTab(t){document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('active',x.dataset.tab===t));
 [['f','pf'],['a','pa'],['d','pd'],['c','pc']].forEach(([k,id])=>$(id).style.display=k===t?'':'none');}
document.querySelectorAll('.tab').forEach(t=>t.onclick=()=>showTab(t.dataset.tab));
document.querySelectorAll('th').forEach(th=>th.onclick=()=>{const k=th.dataset.k;st.dir=st.key===k?-st.dir:1;st.key=k;render();});
$('q').oninput=e=>{st.q=e.target.value;render();};$('host').onchange=e=>{st.host=e.target.value;render();};$('cat').onchange=e=>{st.cat=e.target.value;render();};
$('expand').onclick=()=>{st.all=!st.all;$('expand').textContent=st.all?'Collapse all':'Expand all';render();};
$('csv').onclick=()=>{const q=v=>'"'+String(v).replace(/"/g,'""')+'"';const csv=['severity,host,id,finding,category,ports,evidence,recommendation'].concat(filtered().map(f=>[f.severity,f.host,f.id,f.title,f.category,f.ports.join(' '),f.evidence,f.recommendation].map(q).join(','))).join('\n');
 const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv'}));a.download='findings.csv';a.click();};
function setTheme(t){document.documentElement.dataset.theme=t;try{localStorage.setItem('asa-theme',t);}catch(e){}}
let sv=null;try{sv=localStorage.getItem('asa-theme');}catch(e){}setTheme(sv||(matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light'));
$('theme').onclick=()=>setTheme(document.documentElement.dataset.theme==='dark'?'light':'dark');
drawCards();drawAssets();drawDns();drawChanges();render();
</script></body></html>"""


def save_html(results, findings, summary, diff, outdir):
    data = json.dumps({"results": results, "findings": findings, "summary": summary, "diff": diff}).replace("</", "<\\/")
    doc = TEMPLATE.replace("__DATA__", data).replace("__GENERATED__", results["scanned_at"].replace("T", " "))
    path = os.path.join(outdir, "report.html")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return path
