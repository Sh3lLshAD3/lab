'use strict';
const $=id=>document.getElementById(id);
let token=location.hash.slice(1)||sessionStorage.getItem('lab-token')||'';
if(token){sessionStorage.setItem('lab-token',token);history.replaceState(null,'',location.pathname);}
let jobs=[], selected=null, logSelection=null, polling=false, currentOS=null;
let lastRendered='';const detailsCache=new Map();let inventoryData=null, inventoryBusy=false;
const coreTools=['subfinder','httpx','waybackurls','dalfox','ffuf','arjun','sqlmap','nuclei','nikto'];
const scanTools=[...coreTools,'katana','dnsrecon','nmap','dnsx','naabu','photon','theHarvester'];
const installable=scanTools;let setupInventoryLoaded='';
const manualToolGuides={subfinder:'https://github.com/projectdiscovery/subfinder',httpx:'https://github.com/projectdiscovery/httpx',waybackurls:'https://github.com/tomnomnom/waybackurls',dalfox:'https://github.com/hahwul/dalfox',ffuf:'https://github.com/ffuf/ffuf',arjun:'https://github.com/s0md3v/Arjun',sqlmap:'https://github.com/sqlmapproject/sqlmap',nuclei:'https://github.com/projectdiscovery/nuclei',nikto:'https://github.com/sullo/nikto',katana:'https://github.com/projectdiscovery/katana',dnsrecon:'https://github.com/darkoperator/dnsrecon',nmap:'https://nmap.org/download.html',dnsx:'https://github.com/projectdiscovery/dnsx',naabu:'https://github.com/projectdiscovery/naabu',photon:'https://github.com/s0md3v/Photon#readme',theHarvester:'https://github.com/laramies/theHarvester/wiki/Installation'};
const isSetup=location.pathname==='/setup';
$('setup-view').hidden=!isSetup;$('search-view').hidden=isSetup;
function node(tag,text,cls){const el=document.createElement(tag);if(text!==undefined)el.textContent=text;if(cls)el.className=cls;return el;}
function error(text){$('error').textContent=text;$('error').hidden=false;setTimeout(()=>$('error').hidden=true,9000);}
async function api(path,data){const r=await fetch(path,{method:data?'POST':'GET',headers:{'X-Lab-Token':token,...(data?{'Content-Type':'application/json'}:{})},body:data?JSON.stringify(data):undefined});if(!r.ok){let message='Request failed';try{message=(await r.json()).error||message;}catch{}throw new Error(message);}return r.json();}
$('setup-link').onclick=()=>window.open('/setup#'+token,'_blank');
$('scope-toggle').onclick=()=>$('scope-panel').hidden=!$('scope-panel').hidden;
$('scan-form').onsubmit=async event=>{event.preventDefault();try{const data={url:$('target').value,hosts:$('hosts').value,authorized:$('authorized').checked,options:{crawl_depth:Number($('crawl-depth').value),top_ports:Number($('top-ports').value),harvester_sources:$('harvester-sources').value.split(',')},tools:[...document.querySelectorAll('[data-scan-tool]:checked')].map(el=>el.dataset.scanTool)};for(const key of ['urls','roots','endpoints','parameters'])data[key]=Number($(key).value);const r=await api('/api/scan',data);selected=r.id;logSelection=null;await refresh();$('workspace').scrollIntoView({behavior:'smooth',block:'start'});}catch(e){error(e.message);}};
function button(text,handler,cls='button outline'){const b=node('button',text,cls);b.onclick=handler;return b;}
function active(job){return ['queued','running'].includes(job.status);}
async function stop(job){try{await api('/api/stop/'+job.id,{});await refresh();}catch(e){error(e.message);}}
async function download(job,format='docx'){try{const r=await fetch('/api/report/'+job.id+(format==='html'?'/html':''),{headers:{'X-Lab-Token':token}});if(!r.ok)throw new Error((await r.json()).error);const blob=await r.blob();const link=node('a');link.href=URL.createObjectURL(blob);link.download='pentest-report-'+job.id.slice(0,8)+'.'+format;link.click();setTimeout(()=>URL.revokeObjectURL(link.href),10000);}catch(e){error(e.message);}}
function render(){
 const scans=jobs.filter(j=>j.kind==='scan');if(!selected&&scans.length)selected=scans[0].id;
 $('history').replaceChildren();for(const j of scans){let host;try{host=new URL(j.target).host;}catch{host=j.target;}const b=button('',()=>{selected=j.id;logSelection=null;refresh();},j.id===selected?'active':'');b.append(node('b',host),node('small',j.status+' · '+new Date(j.created).toLocaleString()));$('history').append(b);}
 const job=scans.find(j=>j.id===selected);if(!job)return;
 renderMonitor(job);
 const signature=job.id+':'+job.revision+':'+$('result-filter').value;if(signature===lastRendered){return;}lastRendered=signature;
 $('job-title').textContent=job.target;$('job-actions').replaceChildren();
 if(active(job))$('job-actions').append(button('Stop',()=>stop(job)));
 else $('job-actions').append(button('Read report',()=>previewReport(job)),button('↓ Word',()=>download(job),'button primary'),button('HTML',()=>download(job,'html')));
 const done=(job.stages||[]).filter(s=>s.status==='done').length;
 const running=(job.stages||[]).filter(s=>s.status==='running').map(s=>s.name).join(', ');
 const summary=node('div',(job.version?'v'+job.version+' · ':'')+job.status.toUpperCase()+' · '+done+' checks completed'+(running?' · Running '+running:'')+(job.routing?' · '+job.routing.live+' live URLs':''),'status-line');
 if(job.error)summary.append(node('div',job.error));if(job.excluded_hosts?.length)summary.append(node('div',job.excluded_hosts.length+' discovered hosts excluded from the configured scope.'));
 if(job.summary)summary.append(node('div',job.summary.observations+' recon observations · '+job.summary.candidates+' vulnerability candidates'));
 $('pipeline-status').replaceChildren();for(const [tool,cover] of Object.entries(job.coverage||{})){const item=node('span',tool+' · '+cover.state,'phase-chip '+cover.state.replaceAll(' ','-'));item.title=cover.phase+' · '+(cover.detail||'');$('pipeline-status').append(item);}
 if(job.report_error)summary.append(node('div','Report error: '+job.report_error));$('job-summary').replaceChildren(summary);
 const opened=new Set([...$('findings').querySelectorAll('details[open]')].map(el=>el.dataset.key));
 const visibleFindings=job.findings.filter(f=>$('result-filter').value==='all'||(f.kind||'candidate')===$('result-filter').value);
 $('findings').replaceChildren();if(!visibleFindings.length){const e=node('div',undefined,'empty');e.append(node('div','⌕','empty-icon'),node('h3',active(job)?'Assessment in progress':job.findings.length?'No results for this filter':'No findings recorded'),node('p',active(job)?'New results appear here as each tool finishes.':'Review coverage below. Missing or incomplete checks do not establish that the target is secure.'));$('findings').append(e);}
 for(const f of visibleFindings){const card=node('article',undefined,'finding');const heading=node('div',undefined,'finding-head');heading.append(node('h3',f.title),node('span',f.severity,'badge '+f.severity));card.append(heading,node('div',f.url,'url'),node('p',f.tool+' · '+(f.kind==='observation'?'Recon observation':'Automated candidate; review required')));const detail=node('details');detail.dataset.key=f.tool+'|'+f.url+'|'+f.title;detail.open=opened.has(detail.dataset.key);detail.append(node('summary','View evidence'),node('pre',f.evidence));card.append(detail);$('findings').append(card);}
 $('technical').hidden=false;$('coverage').replaceChildren();for(const s of job.stages||[]){const row=node('div',undefined,'stage');row.append(node('span',s.name+' · '+s.status+' · '+(s.detail||'')));if(s.log)row.append(button('Log',()=>{$('follow-tool').checked=false;logSelection={id:job.id,name:s.log};loadLog();},''));$('coverage').append(row);}
}
async function loadLog(){const selection=logSelection;if(!selection)return;try{const v=await api('/api/log/'+selection.id+'/'+selection.name);$('scan-log').hidden=false;if(!logSelection||logSelection.id!==selection.id||logSelection.name!==selection.name)return;$('scan-log').textContent=v.text||'Waiting for tool output…';$('live-log-title').textContent='Live output · '+selection.name;if($('follow-log').checked)$('scan-log').scrollTop=$('scan-log').scrollHeight;}catch(e){error(e.message);}}
async function setup(platform){try{const tools=[...document.querySelectorAll('[data-install-tool]:checked')].map(el=>el.dataset.installTool);if(!tools.length)throw new Error('Select at least one tool from the inventory');const r=await api('/api/setup',{platform,tools,update:$('update-tools').checked});selected=r.id;await refresh();}catch(e){error(e.message);}}
$('windows-choice').onclick=()=>$('windows-options').hidden=!$('windows-options').hidden;
$('linux-choice').onclick=()=>setup('linux');$('wsl-choice').onclick=()=>setup('wsl');$('native-choice').onclick=()=>setup('windows');
async function renderSetup(){
 const job=jobs.find(j=>j.kind==='setup');if(!job)return;
 const status=$('setup-status');status.replaceChildren(node('span',job.platform.toUpperCase()+' · '+job.status.toUpperCase()+(job.error?' · '+job.error:'')));
 if(active(job))status.append(button('Stop installation',()=>stop(job)));
 try{const data=await api('/api/log/'+job.id+'/setup.log');$('setup-log').textContent=data.text||'Starting installer…';if(data.installation)renderInstallProgress(data.installation);$('setup-log').scrollTop=$('setup-log').scrollHeight;}catch(e){if(!active(job))$('setup-log').textContent=job.error||'No installer output was recorded.';}
 if(!active(job)){
  if(setupInventoryLoaded!==job.id){const detail=await api('/api/job/'+job.id);if(detail.inventory)renderInventory(detail.inventory);setupInventoryLoaded=job.id;}
  $('setup-report-actions').replaceChildren(button('Download setup TXT',()=>downloadSetup(job,'txt')),button('Download setup JSON',()=>downloadSetup(job,'json')));
 }
}
async function downloadSetup(job,format){try{const response=await fetch('/api/setup-report/'+job.id+'?format='+format,{headers:{'X-Lab-Token':token}});if(!response.ok)throw new Error((await response.json()).error);const link=node('a');link.href=URL.createObjectURL(await response.blob());link.download='lab-setup-'+job.id.slice(0,8)+'.'+format;link.click();setTimeout(()=>URL.revokeObjectURL(link.href),10000);}catch(e){error(e.message);}}
async function refresh(){if(polling)return;polling=true;try{const state=await api('/api/state');jobs=state.jobs.map(j=>({...detailsCache.get(j.id),...j}));currentOS=state.os;$('version').textContent='v'+(state.version||'3.1.2');
 if(!isSetup){const scan=jobs.find(j=>j.id===selected&&j.kind==='scan')||jobs.find(j=>j.kind==='scan');if(scan){selected=scan.id;const cached=detailsCache.get(scan.id);if(!cached||cached.revision!==scan.revision){const detail=await api('/api/job/'+scan.id);detailsCache.set(scan.id,detail);jobs=jobs.map(j=>j.id===scan.id?detail:j);}}}
 $('runtime-choice').value=state.runtime;$('runtime-choice').disabled=state.busy;$('runtime-choice').querySelector('[value=wsl]').disabled=state.os!=='windows';$('runtime').textContent=state.os.toUpperCase()+' / '+state.runtime.toUpperCase();$('scan-button').disabled=state.busy;for(const id of ['linux-choice','native-choice','wsl-choice'])$(id).disabled=state.busy; if(currentOS==='windows')$('linux-choice').disabled=true;else{$('windows-choice').disabled=true;$('native-choice').disabled=true;$('wsl-choice').disabled=true;}if(isSetup)await renderSetup();else render();}catch(e){error(e.message);}finally{polling=false;}}
const scanToolPanel=$('scan-tools');
if(scanToolPanel){for(const name of scanTools){const label=node('label',undefined,'check');const input=node('input');input.type='checkbox';input.dataset.scanTool=name;input.checked=true;input.disabled=name==='httpx';label.append(input,document.createTextNode(name+(name==='httpx'?' (required)':'')));scanToolPanel.append(label);}}
function renderInventory(data){
 inventoryData=data;const selected=new Set([...document.querySelectorAll('[data-install-tool]:checked')].map(x=>x.dataset.installTool));const hadRows=$('inventory-rows').children.length>0;$('inventory-rows').replaceChildren();
 for(const tool of data.tools){const tr=node('tr');const td=node('td');if(installable.includes(tool.name)){const check=node('input');check.type='checkbox';check.dataset.installTool=tool.name;check.checked=hadRows?selected.has(tool.name):!tool.verified;check.setAttribute('aria-label','Install '+tool.name);td.append(check);}else if(manualToolGuides[tool.name]){const link=node('a',tool.installed?'Update guide ↗':'Install guide ↗');link.href=manualToolGuides[tool.name];link.target='_blank';link.rel='noopener noreferrer';link.title='Official instructions; installation or update is manual';td.append(link);}else td.textContent='—';tr.append(td,node('td',tool.name),node('td',tool.installed?'Found':'Not installed'),node('td',tool.version),node('td',tool.verified?'OK':!tool.required&&!tool.installed?'Optional — not installed':'Needs attention'));tr.lastChild.title=tool.detail;tr.children[3].title=tool.path;tr.tabIndex=0;const show=()=>showInventoryDetail(tool);tr.onclick=e=>{if(!['INPUT','A'].includes(e.target.tagName))show();};tr.onkeydown=e=>{if(e.key==='Enter')show();};if(manualToolGuides[tool.name]){const guide=node('a',' Guide ↗');guide.href=manualToolGuides[tool.name];guide.target='_blank';guide.rel='noopener noreferrer';tr.children[1].append(guide);}tr.dataset.tool=tool.name;$('inventory-rows').append(tr);}
 renderDependencies(data.dependencies||[]);
 $('inventory-summary').textContent=data.tools.filter(t=>t.required&&t.verified).length+'/'+coreTools.length+' core tools verified; '+data.tools.filter(t=>t.verified).length+'/'+scanTools.length+' total verified. Select a row checkbox to install or repair it.';
}
function renderInstallProgress(status){$('setup-progress').value=status.total?Math.round(100*(status.completed||0)/status.total):0;for(const item of status.tools){const row=[...$('inventory-rows').children].find(r=>r.dataset.tool===item.name);if(row){row.children[2].textContent=item.state;if(item.version)row.children[3].textContent=item.version;row.children[4].textContent=item.verified?'OK':item.state==='failed'?'Failed':'Pending';row.children[4].title=item.detail||'';row.dataset.installState=item.state;row.className='tool-status '+(item.verified?'done':item.state==='failed'?'failed':['installing','checking','downloading'].includes(item.state)?'running':'pending');}}}
async function checkTools(force=false){if(inventoryBusy)return;inventoryBusy=true;$('recheck-tools').disabled=true;try{renderInventory(await api('/api/tools'+(force?'?refresh=1':'')));}catch(e){$('inventory-summary').textContent=e.message;}finally{inventoryBusy=false;$('recheck-tools').disabled=false;}}
$('recheck-tools').onclick=()=>checkTools(true);
$('select-core').onclick=()=>document.querySelectorAll('[data-install-tool]').forEach(x=>x.checked=coreTools.includes(x.dataset.installTool));
$('select-missing').onclick=()=>document.querySelectorAll('[data-install-tool]').forEach(x=>x.checked=Boolean(inventoryData?.tools.find(t=>t.name===x.dataset.installTool&&t.required&&!t.verified)));
$('runtime-choice').onchange=async()=>{try{await api('/api/runtime',{runtime:$('runtime-choice').value});await refresh();await checkTools(true);}catch(e){error(e.message);}};
refresh();if(isSetup)checkTools();setInterval(()=>{if(!document.hidden)refresh();},1000);
document.addEventListener('visibilitychange',()=>{if(!document.hidden)refresh();});

function showInventoryDetail(item){$('inventory-detail').hidden=false;$('inventory-detail').textContent=[item.name,item.purpose||'', 'Path: '+(item.path||item.package||'Unknown'),'Source: '+(item.source||'OS package or published tool'),'Check: '+(item.command||[]).join(' '),item.detail||''].join('\n');}
function renderDependencies(items){$('dependency-rows').replaceChildren();for(const item of items){const row=node('tr');row.append(node('td',item.name),node('td',item.package||''),node('td',item.version||'Unknown'),node('td',item.verified?'OK':'Missing'),node('td',item.setup||(item.verified?'Already installed':'Not installed')));row.tabIndex=0;row.onclick=()=>showInventoryDetail(item);row.onkeydown=e=>{if(e.key==='Enter')showInventoryDetail(item);};$('dependency-rows').append(row);}$('dependency-summary').textContent=items.filter(x=>x.verified).length+'/'+items.length+' components verified';}
$('select-all-tools').onclick=()=>document.querySelectorAll('[data-install-tool]').forEach(x=>x.checked=true);
$('scan-full').onclick=()=>document.querySelectorAll('[data-scan-tool]').forEach(x=>x.checked=true);
$('scan-core').onclick=()=>document.querySelectorAll('[data-scan-tool]').forEach(x=>x.checked=coreTools.includes(x.dataset.scanTool));
$('result-filter').onchange=()=>render();

function previewReport(job){const body=$('report-preview-body');body.replaceChildren(node('h2','Pentest Lab '+(job.version||'')+' Report'),node('p','Target: '+job.target),node('p','Status: '+job.status),node('p','Automated results require manual validation.'));for(const [name,item] of Object.entries(job.coverage||{}))body.append(node('p',name+' · '+item.state));for(const item of job.findings||[])body.append(node('h3',item.title),node('p',item.tool+' · '+item.url),node('pre',item.evidence));$('report-preview').showModal();}
$('report-preview-close').onclick=()=>$('report-preview').close();

function renderMonitor(job){
 $('scan-monitor').hidden=false;
 const stages=job.stages||[],running=stages.filter(s=>s.status==='running');
 const counts={done:0,failed:0,running:0};for(const s of stages){if(s.status==='done')counts.done++;if(['failed','timed out'].includes(s.status))counts.failed++;if(s.status==='running')counts.running++;}
 $('scan-counts').textContent=counts.running+' running · '+counts.done+' successful · '+counts.failed+' failed';
 const duration=s=>{if(!s.started)return '';const end=s.finished?Date.parse(s.finished):active(job)?Date.now():Date.parse(job.finished||job.created);return Math.max(0,Math.floor((end-Date.parse(s.started))/1000))+'s';};
 $('active-tool').textContent=running.length?'Running: '+running.map(s=>s.name+' · '+duration(s)).join(', '):active(job)?'Preparing next tool…':'Assessment '+job.status;
 $('scan-tool-rows').replaceChildren();
 const names=Object.keys(job.coverage||{}).length?Object.keys(job.coverage):job.tools||[...new Set(stages.map(s=>s.name))];
 for(const name of names){const attempts=stages.filter(s=>s.name===name),last=attempts.at(-1),cover=job.coverage?.[name];const state=cover?.state||last?.status||'pending';const row=node('tr',undefined,'tool-status '+state.replaceAll(' ','-'));row.append(node('td',name),node('td',state==='done'?'Success':state),node('td',attempts.length+' / '+attempts.filter(s=>s.status==='done').length+' / '+attempts.filter(s=>['failed','timed out'].includes(s.status)).length),node('td',(cover?.detail||last?.detail||'')+(last?.started?' · '+duration(last):'')));if(last?.log)row.children[0].append(button('View log',()=>{$('follow-tool').checked=false;logSelection={id:job.id,name:last.log};loadLog();},'button outline'));$('scan-tool-rows').append(row);}
 const chosen=running.filter(s=>s.log).at(-1)||stages.filter(s=>s.log).at(-1);
 if($('follow-tool').checked&&chosen)logSelection={id:job.id,name:chosen.log};
 if(logSelection?.id===job.id)loadLog();else{$('scan-log').textContent='Waiting for tool output…';$('live-log-title').textContent='Live output';}
}
