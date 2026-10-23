"""Bounded local CLI verification; no scan targets are passed to probes."""
import os
import re
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from catalog import CHECKS, CORE, SOURCES
from runtime import Runtime, kill_tree
from dependencies import inspect_dependencies
ANSI=re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
_LOCK=threading.Lock()
_CACHE={}

def probe(runtime,name):
    command=runtime.command(name)
    result={'source':SOURCES.get(name,''),'name':name,'required':name in CORE,'installed':bool(command),'verified':False,
            'command':(command or [])+CHECKS[name],'path':command[0] if command else '', 'version':'Not installed','detail':'Not found'}
    if not command:return result
    proc=None
    try:
        proc=subprocess.Popen(runtime.wrap(command+CHECKS[name]),stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
            cwd=runtime.workdir(name),start_new_session=os.name!='nt',creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
        try:output,_=proc.communicate(timeout=12)
        except subprocess.TimeoutExpired:
            kill_tree(proc);proc.communicate();result.update(version='Unknown',detail='Verification timed out');return result
        text=ANSI.sub('',output.decode('utf-8',errors='replace'))[:8000]
        valid=proc.returncode==0
        # waybackurls uses Go's flag help exit code 2 for -h.
        if name=='waybackurls':valid=proc.returncode in (0,2) and 'Usage' in text
        if name=='httpx':
            valid=valid and 'httpx' in text.lower() and 'projectdiscovery' in text.lower()
            if not valid:
                help_result=subprocess.run(runtime.wrap(command+['-h']),capture_output=True,text=True,timeout=12)
                help_text=help_result.stdout+help_result.stderr
                valid=help_result.returncode==0 and '-tech-detect' in help_text and '-json' in help_text
                if not valid:text+='\nNot identified as ProjectDiscovery httpx'
        result.update(verified=valid,version=next((line.strip() for line in text.splitlines() if re.search(r'\d+\.\d+',line)), 'Available; version not reported'),detail=text.strip() or f'Exit code {proc.returncode}')
    except (OSError,subprocess.SubprocessError) as exc:
        result.update(version='Unknown',detail=str(exc))
        if proc:kill_tree(proc)
    return result

def inspect(mode='native',refresh=False):
    with _LOCK:
        cached=_CACHE.get(mode)
        if cached and not refresh and time.monotonic()-cached[0]<60:return cached[1]
        runtime=Runtime(mode)
        with ThreadPoolExecutor(max_workers=3) as pool:items=list(pool.map(lambda name:probe(runtime,name),CHECKS))
        result={'tools':items,'dependencies':inspect_dependencies(runtime),'all_ok':all(x['verified'] for x in items if x['required'])}
        _CACHE[mode]=(time.monotonic(),result)
        return result
