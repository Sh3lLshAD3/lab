"""Scoped JavaScript downloads followed by offline SecretFinder CLI analysis."""
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import build_opener, HTTPRedirectHandler, Request
import time

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):return None

def javascript_urls(scope,urls,limit):
    return [u for u in scope.filter(urls) if urlsplit(u).path.lower().endswith(('.js','.mjs','.cjs'))][:limit]

def download(url,cancel):
    chunks=[];size=0
    with build_opener(NoRedirect).open(Request(url,headers={'User-Agent':'PentestLab/3.2','Accept-Encoding':'identity'}),timeout=10) as response:
        while True:
            if cancel.is_set():raise InterruptedError('Stopped by user')
            chunk=response.read(65536)
            if not chunk:break
            size+=len(chunk)
            if size>8_000_000:raise ValueError('JavaScript exceeds 8 MB download limit')
            chunks.append(chunk)
    return b''.join(chunks)

def scan(worker,urls,read_lines,now):
    if 'secretfinder' not in worker.enabled:return
    targets=javascript_urls(worker.scope,urls,worker.job['limits']['urls'])
    worker.job['javascript_targets']=targets
    worker.file('javascript-targets.txt',targets)
    if not targets:
        worker.job['stages'].append({'name':'secretfinder','status':'not applicable','detail':'No in-scope .js/.mjs/.cjs URLs discovered'});worker.checkpoint();return
    if not worker.runtime.command('secretfinder'):
        worker.run('secretfinder',['-h']);return
    for index,url in enumerate(targets):
        if worker.cancel.is_set():return
        stage={'name':'secretfinder','status':'running','execution_kind':'download','detail':'Downloading '+url,'started':now()}
        worker.job['stages'].append(stage);worker.checkpoint()
        try:
            content=download(url,worker.cancel)
            local=worker.directory/f'javascript-{index}.js';local.write_bytes(content)
            stage.update(status='done',detail='Downloaded '+url,finished=now());worker.checkpoint()
        except Exception as exc:
            stage.update(status='cancelled' if worker.cancel.is_set() else 'failed',detail=url+': '+str(exc),finished=now());worker.checkpoint();continue
        log=worker.run('secretfinder',['-i',worker.rp(local),'-o','cli'],timeout=None)
        if not log:continue
        for line in read_lines(log):
            if '\t->\t' not in line:continue
            category,value=line.split('\t->\t',1)
            if category.strip() and value.strip():
                worker.finding('secretfinder','Possible JavaScript secret: '+category.strip(),url,value.strip(),'unverified')
