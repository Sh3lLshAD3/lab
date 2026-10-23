"""Sequential background pipeline with bounded external processes and evidence."""
import json
import ipaddress
import xml.etree.ElementTree as ET
import os
import re
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit, urlencode
from scope import Scope, route, normalize, origin, dedupe_parameters
from runtime import ROOT, Runtime, kill_tree, prepare_wsl_group, stop_process
from report import export
from catalog import CORE,SCANNABLE,PHASES
from version import VERSION
import recon
from inventory import probe

def now(): return datetime.now(timezone.utc).isoformat(timespec='seconds')

def records(path):
    try: text=Path(path).read_text(encoding='utf-8',errors='replace')
    except OSError: return []
    try:
        value=json.loads(text)
        return value if isinstance(value,list) else [value]
    except ValueError:
        result=[]
        for line in text.splitlines():
            try: result.append(json.loads(line))
            except ValueError: pass
        return result

def lines(path):
    try: return Path(path).read_text(encoding='utf-8',errors='replace').splitlines()
    except OSError: return []

class Engine:
    def __init__(self,job,save,cancel):
        self.job=job; self.save=save; self.cancel=cancel
        self.directory=ROOT/'data'/job['id']; self.directory.mkdir(parents=True,exist_ok=True)
        self.runtime=Runtime(job.get('runtime','native'))
        self.scope=Scope(job['target'], job['scope'])
        self.current=None; self.counter=0
        self.enabled=set(job.get('tools',CORE))
        self.finding_keys=set()
        self.last_finding_save=0
        self._httpx_verified=False
    def checkpoint(self):
        coverage={name:{'state':'pending' if name in self.enabled else 'not selected','phase':PHASES.get(name,'Other')} for name in SCANNABLE}
        priority={'failed':7,'timed out':6,'cancelled':5,'running':8,'skipped':3,'done':2,'not applicable':1}
        for stage in self.job.get('stages',[]):
            if stage['name'] not in coverage:continue
            item=coverage[stage['name']]
            if priority.get(stage['status'],0)>=priority.get(item['state'],0):item.update(state=stage['status'],detail=stage.get('detail',''))
        for name,item in coverage.items():
            attempts=[s for s in self.job.get('stages',[]) if s['name']==name]
            item['attempts']=len(attempts)
            item['successes']=sum(s['status']=='done' for s in attempts)
            item['failures']=sum(s['status'] in ('failed','timed out') for s in attempts)
        if self.job.get('status','running') not in ('running','queued'):
            for item in coverage.values():
                if item['state']=='pending':item.update(state='not applicable',detail='No eligible targets or an upstream phase did not complete')
        self.job['coverage']=coverage
        self.job['summary']={'observations':sum(f.get('kind')=='observation' for f in self.job['findings']),'candidates':sum(f.get('kind')!='observation' for f in self.job['findings']),'open_ports':len(self.job.get('port_records',[]))}
        self.save(self.job)
    def parse_warning(self,tool,text):
        self.job['stages'].append({'name':tool,'status':'failed','detail':text});self.checkpoint()

    def finding(self,tool,title,url,evidence,severity='info'):
        if not self.scope.allows(url): return
        key=(tool,title,normalize(url),str(evidence)[:6000])
        if key in self.finding_keys:return
        self.finding_keys.add(key)
        kind='candidate' if tool in ('dalfox','sqlmap','nuclei','nikto') else 'observation'
        item={'kind':kind,'tool':tool,'title':title,'url':url,'severity':severity,
              'evidence':str(evidence)[:6000], 'recommendation': 'Review the raw evidence and reproduce in the authorized lab. Apply the relevant input validation, access control or configuration fix after validation.'}
        self.job['findings'].append(item)
        if time.monotonic()-self.last_finding_save>.25:
            self.checkpoint();self.last_finding_save=time.monotonic()
    def run(self,tool,args,stdin=None,timeout=600):
        if self.cancel.is_set() or tool not in self.enabled: return None
        self.counter+=1
        stage={'name':tool,'status':'running','detail':'', 'started':now()}
        self.job['stages'].append(stage); self.checkpoint()
        command=self.runtime.command(tool)
        logfile=self.directory/f'{self.counter:03d}-{tool}.log'
        stage['log']=logfile.name
        if tool=='httpx' and command and not self._httpx_verified:
            check=probe(self.runtime,'httpx')
            if not check['verified']:
                stage.pop('log',None)
                stage.update(finished=now(),status='failed',detail='ProjectDiscovery httpx verification failed: '+check['detail'][:250]);self.checkpoint();return None
            self._httpx_verified=True
        if not command:
            stage.pop('log',None)
            stage.update(finished=now(),status='skipped',detail='Tool missing. Run Setup and retry.'); self.checkpoint(); return None
        pidfile=self.directory/f'{self.counter:03d}-{tool}.pid'
        argv=prepare_wsl_group(self.runtime,command+args,pidfile)
        stage['command']=argv
        logfile.touch()
        self.checkpoint()  # Publish the active log before launching the process.
        proc=None
        try:
            with logfile.open('wb') as out:
                proc=subprocess.Popen(argv,stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                    stdout=out,stderr=subprocess.STDOUT,env={**os.environ,'PYTHONUNBUFFERED':'1'},cwd=self.runtime.workdir(tool), start_new_session=os.name!='nt',
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
                if stdin is not None:
                    try: proc.stdin.write(stdin.encode()); proc.stdin.close()
                    except BrokenPipeError: pass
                deadline=time.monotonic()+timeout
                while proc.poll() is None:
                    if self.cancel.wait(.2):
                        stop_process(self.runtime,proc,pidfile); stage.update(status='cancelled',detail='Stopped by user'); break
                    if time.monotonic()>deadline or logfile.stat().st_size>50_000_000:
                        stop_process(self.runtime,proc,pidfile); stage.update(status='timed out',detail='Time or log size limit reached'); break
                proc.wait(timeout=15)
            if stage['status']=='running':
                stage.update(status='done' if proc.returncode==0 else 'failed',detail=f'Exit code {proc.returncode}')
            stage['log']=logfile.name
        except Exception as exc:
            if proc is not None: stop_process(self.runtime,proc,pidfile)
            stage.update(status='failed',detail=str(exc))
        stage['finished']=now(); self.checkpoint()
        return logfile
    def file(self,name,items):
        p=self.directory/name; p.write_text('\n'.join(items)+'\n',encoding='utf-8'); return p
    def rp(self,path): return self.runtime.path(path)
    def execute(self):
        self.job['status']='running'
        self.job['version']=VERSION
        self.job['disabled_tools']=sorted(set(SCANNABLE)-self.enabled)
        self.checkpoint()
        try:
            self.pipeline()
            if self.cancel.is_set(): self.job['status']='cancelled'
            elif any(s['status'] in ('failed','skipped','timed out') for s in self.job['stages']): self.job['status']='partial'
            else: self.job['status']='complete'
        except Exception as exc:
            self.job['status']='failed'; self.job['error']=str(exc)
            for stage in self.job['stages']:
                if stage['status']=='running':stage.update(status='failed',detail=str(exc))
        self.job['finished']=now(); self.checkpoint()
        try: export(self.job,self.directory/'report.docx')
        except Exception as exc: self.job['report_error']=str(exc)
        self.checkpoint()
    def pipeline(self):
        target=self.scope.seed; host=urlsplit(target).hostname
        urls={target}; discovered_hosts=set()
        archived,discovered_hosts=recon.passive(self,host,records,lines)
        urls.update(self.scope.filter(archived))
        self.job['discovered_hosts']=sorted(discovered_hosts)
        self.job['excluded_hosts']=sorted(h for h in discovered_hosts if h not in self.scope.hosts)
        for h in sorted(discovered_hosts):
            if h.lower() in self.scope.hosts: urls.add('https://'+h+'/')
        for h in self.scope.hosts - {host}: urls.add('https://'+('['+h+']' if ':' in h else h)+'/')
        filtered=dedupe_parameters([target]+[u for u in self.scope.filter(urls) if u!=target])
        # Keep the explicitly entered URL even when archive limits are reached.
        urls=[target]+[u for u in filtered if u!=target][:self.job['limits']['urls']-1]
        self.job['discovery_counts']={'in_scope':len(filtered),'selected':len(urls),'excluded_by_limit':max(0,len(filtered)-len(urls))}
        urls=recon.dns_and_ports(self,urls,records,lines)
        if self.cancel.is_set():return
        candidates=self.file('candidates.txt',urls)
        probe=self.directory/'httpx.jsonl'
        self.run('httpx',['-l',self.rp(candidates),'-json','-silent','-rl','3','-t','2','-timeout','10','-o',self.rp(probe)])
        # No redirect-follow flags: each submitted URL must pass the host scope check.
        live=self.scope.filter([r.get('url','') for r in records(probe) if isinstance(r,dict) and r.get('status_code',0)])
        if not live:
            self.job['stages'].append({'name':'routing','status':'skipped','detail':'No live URLs from httpx; active stages were not run.'}); self.checkpoint(); return
        extra=recon.crawl(self,live,route(live)['roots'][:self.job['limits']['roots']],lines)
        self.file('crawler-candidates.txt',extra)
        if extra and not self.cancel.is_set():
            candidates=self.file('crawler-probe.txt',extra);output=self.directory/'crawler-httpx.jsonl'
            self.run('httpx',['-l',self.rp(candidates),'-json','-silent','-rl','3','-t','2','-timeout','10','-o',self.rp(output)])
            live=self.scope.filter(live+[r.get('url','') for r in records(output) if isinstance(r,dict) and r.get('status_code',0)])
        live=dedupe_parameters(live)[:self.job['limits']['urls']]
        routed=route(live)
        roots=routed['roots'][:self.job['limits']['roots']]
        endpoints=routed['endpoints'][:self.job['limits']['endpoints']]
        parameters=dedupe_parameters(routed['parameters'])[:self.job['limits']['parameters']]
        self.job['routing_limits']={key:{'available':len(routed[source]),'selected':len(selected)} for key,source,selected in [('roots','roots',roots),('endpoints','endpoints',endpoints),('parameters','parameters',parameters)]}
        self.job['live_hosts']=sorted({urlsplit(u).hostname for u in live})
        self.job['routing']={'live':len(live),'roots':len(roots),'endpoints':len(endpoints),'parameters':len(parameters)}
        self.file('live.txt',live); self.checkpoint()
        # Initial Dalfox pass on existing query strings.
        scanned=set()
        def dalfox(url):
            output=self.directory/f'dalfox-{len(scanned)}.json'
            self.run('dalfox',['url',url,'--format','json','--silence','--worker','1','--delay','350','--skip-mining-all','--output',self.rp(output)])
            scanned.add(url)
            for r in records(output):
                if not isinstance(r,dict): continue
                # Dalfox v2 emits individual PoCs; newer builds may wrap them.
                items=r.get('pocs',[r])
                for item in items if isinstance(items,list) else []:
                    if isinstance(item,dict) and (item.get('poc') or item.get('payload')):
                        self.finding('dalfox','Potential cross site scripting',url,json.dumps(item,ensure_ascii=False),'unverified')
        for url in parameters:
            if self.cancel.is_set(): return
            dalfox(url)
        # ffuf is directory discovery, not a vulnerability finding by itself.
        discovered=[]
        for i,root in enumerate(roots):
            output=self.directory/f'ffuf-{i}.json'
            self.run('ffuf',['-w',self.rp(ROOT/'wordlists/paths.txt'),'-u',root+'FUZZ','-rate','3','-t','1','-maxtime','120','-ac','-noninteractive','-of','json','-o',self.rp(output)],timeout=150)
            for obj in records(output):
                for r in obj.get('results',[]) if isinstance(obj,dict) else []:
                    url=r.get('url','')
                    if self.scope.allows(url):
                        discovered.append(url)
                        self.finding('ffuf','Discovered web path',url,f"HTTP {r.get('status')} length {r.get('length')}")
        endpoints=sorted(set(endpoints+route(self.scope.filter(discovered))['endpoints']))[:self.job['limits']['endpoints']]
        # Parameter discovery output is fed back into Dalfox and SQLmap.
        expanded=list(parameters)
        for i,url in enumerate(endpoints):
            output=self.directory/f'arjun-{i}.json'
            self.run('arjun',['-u',url,'-m','GET','--stable','-t','1','-d','0.5','-oJ',self.rp(output)],timeout=300)
            for obj in records(output):
                if not isinstance(obj,dict): continue
                for found,info in obj.items():
                    if not self.scope.allows(found) or not isinstance(info,dict): continue
                    params=info.get('params',[])
                    if params:
                        p=urlsplit(normalize(found)); test=urlunsplit((p.scheme,p.netloc,p.path,urlencode([(str(k),'1') for k in params]),''))
                        expanded.append(test)
                        self.finding('arjun','Discovered GET parameters',found,', '.join(map(str,params)))
        expanded=dedupe_parameters(parameters+self.scope.filter(expanded))[:self.job['limits']['parameters']]
        self.file('parameter-targets.txt',expanded)
        for url in expanded:
            if self.cancel.is_set(): return
            if url not in scanned: dalfox(url)
        for i,url in enumerate(expanded):
            output=self.directory/f'sqlmap-{i}'
            log=self.run('sqlmap',['-u',url,'--batch','--level=1','--risk=1','--threads=1','--delay=0.4','--timeout=10','--retries=0','--ignore-redirects','--disable-coloring','--output-dir='+self.rp(output)],timeout=600)
            text='\n'.join(lines(log)) if log else ''
            # Require structured injection summary, not generic warning/error text.
            match=re.search(r'Parameter: .+?\n(?:.*\n){0,2}?\s*Type: .+',text)
            if match: self.finding('sqlmap','Potential SQL injection',url,match.group(0),'unverified')
        if self.cancel.is_set(): return
        targets=self.file('nuclei-targets.txt',roots)
        output=self.directory/'nuclei.jsonl'
        template_args=self.runtime.templates_args()
        self.run('nuclei',['-l',self.rp(targets),'-jsonl','-o',self.rp(output),'-rl','3','-c','1','-ni','-dr','-duc','-timeout','10','-retries','0',*template_args],timeout=900)
        for r in records(output):
            if not isinstance(r,dict):continue
            info=r.get('info',{})
            self.finding('nuclei',info.get('name','Template match'),r.get('matched-at',r.get('host',roots[0])),json.dumps(r,ensure_ascii=False),info.get('severity','unknown'))
        for i,root in enumerate(roots):
            if self.cancel.is_set(): return
            output=self.directory/f'nikto-{i}.json'
            self.run('nikto',['-h',root,'-Format','json','-output',self.rp(output),'-maxtime','300s','-Pause','0.4','-nointeractive'],timeout=330)
            for obj in records(output):
                if not isinstance(obj,dict): continue
                for v in obj.get('vulnerabilities',[]):
                    self.finding('nikto','Potential server configuration issue',root,str(v),'unverified')
