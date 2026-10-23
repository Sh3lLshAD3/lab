"""Local-only browser UI. No scan or installer runs before a user action."""
import copy
import json
import os
import secrets
import subprocess
import sys
import threading
import time
import uuid
import webbrowser
from pathlib import Path
from flask import Flask, request, jsonify, send_file
from engine import Engine, now
from runtime import ROOT, Runtime, kill_tree, prepare_wsl_group, stop_process
from scope import Scope
from report import export
from catalog import CORE, SCANNABLE, INSTALLABLE
from inventory import inspect as inspect_tools
from dependencies import inspect_dependencies
from version import VERSION,APP_NAME

app=Flask(__name__,static_folder='static')
app.config['MAX_CONTENT_LENGTH']=64*1024
TOKEN=secrets.token_urlsafe(32)
PORT=int(os.environ.get('LAB_PORT','8765'))
BASE=f'http://127.0.0.1:{PORT}'
DATA=ROOT/'data'; DATA.mkdir(exist_ok=True)
LOCK=threading.RLock()
JOBS={}; CANCELS={}; THREADS=[]
SETTINGS=ROOT/'settings.json'
try: mode=json.loads(SETTINGS.read_text()).get('runtime','native')
except (OSError,ValueError): mode='native'

for path in DATA.glob('*/job.json'):
    try:
        item=json.loads(path.read_text())
        if item['status'] in ('queued','running'):
            item['status']='interrupted'; item['finished']=now()
            for s in item.get('stages',[]):
                if s['status']=='running': s['status']='interrupted'
            path.write_text(json.dumps(item,indent=2))
        JOBS[item['id']]=item
    except (OSError,ValueError,KeyError): pass

def save(job):
    with LOCK:
        folder=DATA/job['id']; folder.mkdir(exist_ok=True)
        job['revision']=job.get('revision',0)+1
        temp=folder/'job.tmp'; temp.write_text(json.dumps(job,ensure_ascii=True,indent=2),encoding='utf-8')
        temp.replace(folder/'job.json'); JOBS[job['id']]=copy.deepcopy(job)

def busy(): return any(j['status'] in ('queued','running') for j in JOBS.values())

def background(function,*args):
    THREADS[:]=[t for t in THREADS if t.is_alive()]
    thread=threading.Thread(target=function,args=args,daemon=True)
    THREADS.append(thread); thread.start()

@app.before_request
def protect():
    if request.host != f'127.0.0.1:{PORT}': return jsonify(error='Invalid host'),403
    if request.path.startswith('/api/'):
        if not secrets.compare_digest(request.headers.get('X-Lab-Token',''),TOKEN): return jsonify(error='Reopen the app from the launcher'),403
        if request.headers.get('Origin') and request.headers['Origin'] != BASE: return jsonify(error='Invalid origin'),403

@app.after_request
def headers(response):
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['X-Frame-Options']='DENY'
    response.headers['Referrer-Policy']='no-referrer'
    response.headers['Cache-Control']='no-store'
    response.headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    return response

@app.get('/')
@app.get('/setup')
def home(): return app.send_static_file('index.html')

@app.get('/api/state')
def state():
    with LOCK:
        recent=sorted(JOBS.values(),key=lambda x:x['created'],reverse=True)[:100]
        summaries=[{**{k:j[k] for k in ('id','kind','target','platform','status','created','finished','revision','error','log') if k in j},'findings_count':len(j.get('findings',[]))} for j in recent]
        return jsonify(version=VERSION,runtime=mode,os='windows' if os.name=='nt' else 'linux',jobs=summaries,busy=busy())


@app.get('/api/job/<job_id>')
def job_detail(job_id):
    with LOCK:
        job=JOBS.get(job_id)
        if not job:return jsonify(error='Job not found'),404
        if request.args.get('revision')==str(job.get('revision',0)):return jsonify(unchanged=True)
        return jsonify(copy.deepcopy(job))

@app.get('/api/tools')
def tool_inventory():
    return jsonify(inspect_tools(mode,refresh=request.args.get('refresh')=='1'))

@app.post('/api/runtime')
def choose_runtime():
    global mode
    data=request.get_json(silent=True)
    if not isinstance(data,dict):return jsonify(error='Expected a JSON object'),400
    choice=data.get('runtime')
    if choice not in ('native','wsl') or (choice=='wsl' and os.name!='nt'):return jsonify(error='Unsupported runtime'),400
    with LOCK:
        if busy():return jsonify(error='Wait for the running job to finish'),409
        mode=choice;SETTINGS.write_text(json.dumps({'runtime':mode}))
    return jsonify(runtime=mode)

@app.post('/api/scan')
def scan():
    data=request.get_json(silent=True)
    if not isinstance(data,dict):return jsonify(error='Expected a JSON object'),400
    try:
        if data.get('authorized') is not True: raise ValueError('Confirm the target is your lab or an authorized assessment')
        selected=data.get('tools',list(CORE))
        if not isinstance(selected,list) or not selected or 'httpx' not in selected or any(not isinstance(x,str) or x not in SCANNABLE for x in selected):raise ValueError('Invalid scan tool list')
        opts=data.get('options',{})
        if not isinstance(opts,dict):raise ValueError('Options must be an object')
        depth=min(3,max(1,int(opts.get('crawl_depth',2))))
        top=int(opts.get('top_ports',1000))
        if top not in (100,1000):raise ValueError('Top ports must be 100 or 1000')
        providers=opts.get('harvester_sources',['crtsh','otx'])
        if not isinstance(providers,list) or not providers or any(p not in ('crtsh','otx','certspotter') for p in providers):raise ValueError('Unsupported OSINT source')
        options={'crawl_depth':depth,'top_ports':top,'harvester_sources':list(dict.fromkeys(providers))}
        target=data.get('url','')
        if not isinstance(target,str) or not target.strip():raise ValueError('Enter a URL or domain')
        target=target.strip()
        if '://' not in target:target='https://'+target
        scope=Scope(target,str(data.get('hosts','')).splitlines())
        limits={k:min(ceiling,max(1,int(data.get(k,default)))) for k,default,ceiling in [('urls',60,300),('roots',2,10),('endpoints',5,30),('parameters',8,30)]}
    except (ValueError,UnicodeError,TypeError) as exc: return jsonify(error=str(exc)),400
    with LOCK:
        if busy(): return jsonify(error='A scan or setup is already running'),409
        job={'id':uuid.uuid4().hex,'kind':'scan','target':scope.seed,'scope':sorted(scope.hosts),'version':VERSION,'options':options,'limits':limits,'tools':list(dict.fromkeys(selected)),'runtime':mode,'status':'queued','created':now(),'findings':[],'stages':[]}
        event=threading.Event(); CANCELS[job['id']]=event; save(job)
        background(Engine(job,save,event).execute)
    return jsonify(id=job['id']),202

@app.post('/api/stop/<job_id>')
def stop(job_id):
    with LOCK:
        if job_id not in CANCELS: return jsonify(error='Job is no longer running'),404
        CANCELS[job_id].set()
    return jsonify(ok=True)

@app.get('/api/report/<job_id>')
def report(job_id):
    with LOCK: job=copy.deepcopy(JOBS.get(job_id))
    if not job or job['kind']!='scan': return jsonify(error='Scan not found'),404
    if job['status'] in ('running','queued'): return jsonify(error='Wait for completion or stop the scan'),409
    from io import BytesIO
    output=BytesIO(); export(job,output); output.seek(0)
    return send_file(output,mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document',as_attachment=True,download_name=f'pentest-report-{job_id[:8]}.docx')

@app.get('/api/report/<job_id>/html')
def html_report(job_id):
    from html_report import render
    from io import BytesIO
    with LOCK:job=copy.deepcopy(JOBS.get(job_id))
    if not job or job['kind']!='scan':return jsonify(error='Scan not found'),404
    if job['status'] in ('queued','running'):return jsonify(error='Wait for the scan to finish'),409
    return send_file(BytesIO(render(job).encode('utf-8')),mimetype='text/html',as_attachment=True,download_name=f'pentest-report-{job_id[:8]}.html')

@app.get('/api/setup-report/<job_id>')
def setup_report(job_id):
    from io import BytesIO
    with LOCK:job=copy.deepcopy(JOBS.get(job_id))
    if not job or job['kind']!='setup':return jsonify(error='Setup job not found'),404
    if job['status'] in ('queued','running'):return jsonify(error='Wait for setup to finish'),409
    if request.args.get('format')=='json':
        payload=json.dumps(job,ensure_ascii=True,indent=2);extension='json';mime='application/json'
    else:
        content=[APP_NAME+' '+job.get('version',VERSION),'Status: '+job['status'],'Started: '+job['created'],'Selected: '+', '.join(job.get('tools',[]))]
        for group in ('dependencies','tools'):
            content.append('\n'+group.upper())
            for item in job.get('inventory',{}).get(group,[]):content.extend([item['name']+' | '+('OK' if item.get('verified') else 'Missing')+' | '+str(item.get('version','Unknown')),str(item.get('detail',''))])
        if job.get('error'):content.append(job['error'])
        payload='\n'.join(content);extension='txt';mime='text/plain'
    return send_file(BytesIO(payload.encode('utf-8')),mimetype=mime,as_attachment=True,download_name=f'lab-setup-{job_id[:8]}.{extension}')

@app.get('/api/log/<job_id>/<name>')
def log(job_id,name):
    if job_id not in JOBS or Path(name).name != name or not name.endswith('.log'): return jsonify(error='Log not found'),404
    path=DATA/job_id/name
    if not path.is_file(): return jsonify(error='Log not found'),404
    with path.open('rb') as stream:
        stream.seek(max(0,path.stat().st_size-50_000)); text=stream.read().decode('utf-8',errors='replace')
    result={'text':text}
    if name=='setup.log':
        job=JOBS[job_id]
        status_path=Runtime('wsl' if job.get('platform')=='wsl' else 'native').status_path
        try:
            status=json.loads(status_path.read_text())
            from datetime import datetime
            if status.get('updated',0)>=datetime.fromisoformat(job['created']).timestamp():result['installation']=status
        except (OSError,ValueError,KeyError):pass
    return jsonify(result)

def install(job,event):
    global mode
    job['status']='running'; save(job)
    platform=job['platform']; pidfile=DATA/job['id']/'setup.pid'
    logfile=DATA/job['id']/'setup.log'
    runtime=Runtime('native')
    try:job['dependency_baseline']=inspect_dependencies(Runtime('wsl' if platform=='wsl' else 'native'))
    except Exception:job['dependency_baseline']=[]
    if platform=='linux':
        command=['bash',str(ROOT/'setup/install-linux.sh')]
    elif platform=='wsl':
        command=['powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File',str(ROOT/'setup/install-wsl.ps1')]
    else:
        command=['powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File',str(ROOT/'setup/install-windows.ps1')]
    env=os.environ.copy(); env['LAB_PYTHON']=sys.executable
    env['LAB_SELECTED_TOOLS']=','.join(job['tools'])
    env['LAB_UPDATE_TOOLS']='1' if job.get('update') else '0'
    env['PYTHONUNBUFFERED']='1'
    proc=None
    try:
        if platform=='wsl': (ROOT/'data/wsl-setup.pid').unlink(missing_ok=True)
        Runtime('wsl' if platform=='wsl' else 'native').status_path.unlink(missing_ok=True)
        with logfile.open('wb') as out:
            proc=subprocess.Popen(command,stdout=out,stderr=subprocess.STDOUT,stdin=subprocess.DEVNULL,env=env,
                start_new_session=os.name!='nt',creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
            deadline=time.monotonic()+3600
            while proc.poll() is None:
                if event.wait(.5):
                    # WSL setup descendants can outlive the Windows launcher.
                    # The install script writes a process group PID below.
                    if platform=='wsl':
                        stop_process(Runtime('wsl'),proc,ROOT/'data/wsl-setup.pid')
                    else: kill_tree(proc)
                    job['status']='cancelled'; break
                if time.monotonic()>deadline:
                    if platform=='wsl': stop_process(Runtime('wsl'),proc,ROOT/'data/wsl-setup.pid')
                    else: kill_tree(proc)
                    job['status']='timed out'; break
            if job['status']=='running': job['status']='complete' if proc.returncode==0 else 'action required' if proc.returncode==10 else 'failed'
        if job['status']=='complete':
            mode='wsl' if platform=='wsl' else 'native'
            SETTINGS.write_text(json.dumps({'runtime':mode}))
    except Exception as exc:
        if proc: kill_tree(proc)
        job['status']='failed'; job['error']=str(exc)
    if job['status'] in ('complete','failed'):
        try:
            job['inventory']=inspect_tools('wsl' if platform=='wsl' else 'native',refresh=True)
            baseline={x['name']:x for x in job.get('dependency_baseline',[])}
            if job['status']=='complete' and any(not item.get('verified') for item in job['inventory'].get('tools',[]) if item['name'] in job['tools']):job['status']='partial'
            for item in job['inventory'].get('dependencies',[]):item['setup']='Already installed' if baseline.get(item['name'],{}).get('verified') and item.get('verified') else 'Installed' if item.get('verified') else 'Missing'
        except Exception as exc:job['inventory_error']=str(exc)
    job['finished']=now(); job['log']='setup.log'; save(job)

@app.post('/api/setup')
def setup():
    data=request.get_json(silent=True)
    if not isinstance(data,dict):return jsonify(error='Expected a JSON object'),400
    platform=data.get('platform')
    selected=data.get('tools',list(CORE))
    if not isinstance(selected,list) or not selected or any(not isinstance(x,str) or x not in INSTALLABLE for x in selected):return jsonify(error='Invalid install selection'),400
    if platform not in ('windows','wsl','linux'): return jsonify(error='Choose a setup type'),400
    if (os.name=='nt' and platform=='linux') or (os.name!='nt' and platform!='linux'): return jsonify(error='Choose the operating system running this app'),400
    with LOCK:
        if busy(): return jsonify(error='A scan or setup is already running'),409
        job={'id':uuid.uuid4().hex,'kind':'setup','version':VERSION,'platform':platform,'tools':list(dict.fromkeys(selected)),'update':data.get('update') is True,'created':now(),'status':'queued','stages':[],'findings':[],'log':'setup.log'}
        event=threading.Event(); CANCELS[job['id']]=event; save(job); background(install,job,event)
    return jsonify(id=job['id']),202

if __name__=='__main__':
    from temp_storage import configure_temp,describe_temp
    print(describe_temp(configure_temp()),flush=True)
    url=BASE+('/setup#' if os.environ.get('LAB_OPEN_SETUP')=='1' else '/#')+TOKEN
    print('\nPentest Lab: '+url+'\nKeep this local access link private. Ctrl+C stops the server.\n')
    threading.Timer(1,lambda:webbrowser.open(url)).start()
    try: app.run(host='127.0.0.1',port=PORT,debug=False,threaded=True,use_reloader=False)
    finally:
        for event in CANCELS.values(): event.set()
        for thread in THREADS: thread.join(timeout=20)
