"""Fetch a current Linux Go SDK when the available SDK predates toolchain auto."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

def ensure_go(root):
    existing=shutil.which('go')
    if existing:
        result=subprocess.run([existing,'version'],capture_output=True,text=True,timeout=15)
        version=re.search(r'go(\d+)\.(\d+)',result.stdout)
        if result.returncode==0 and version and tuple(map(int,version.groups()))>=(1,21):return existing
    if platform.system()!='Linux':raise RuntimeError('Install a current Go SDK and restart the app')
    arch={'x86_64':'amd64','aarch64':'arm64','amd64':'amd64','arm64':'arm64'}.get(platform.machine().lower())
    if not arch:raise RuntimeError('No supported Go SDK for this CPU')
    print('[RUNNING] Reading official Go release manifest',flush=True)
    with urllib.request.urlopen('https://go.dev/dl/?mode=json',timeout=30) as response:manifest=json.load(response)
    release=next(r for r in manifest if r.get('stable'))
    item=next(f for f in release['files'] if f['os']=='linux' and f['arch']==arch and f['kind']=='archive')
    root=Path(root);root.mkdir(parents=True,exist_ok=True);target=root/release['version']
    if (target/'bin/go').is_file():return str(target/'bin/go')
    with tempfile.TemporaryDirectory(dir=root) as temp:
        temp=Path(temp);archive=temp/'sdk.tar.gz';digest=hashlib.sha256()
        print('[RUNNING] Downloading '+item['filename']+' with SHA-256 verification',flush=True)
        with urllib.request.urlopen('https://go.dev/dl/'+item['filename'],timeout=60) as response,archive.open('wb') as out:
            downloaded=0
            while chunk:=response.read(1024*1024):
                digest.update(chunk);out.write(chunk);downloaded+=len(chunk)
                if downloaded%(8*1024*1024)==0:print(f'[DOWNLOAD] Go SDK {downloaded//(1024*1024)} MiB',flush=True)
        if digest.hexdigest()!=item['sha256']:raise RuntimeError('Go SDK checksum verification failed')
        print('[DONE] Go SDK SHA-256 verified',flush=True)
        with tarfile.open(archive,'r:gz') as tar:
            for m in tar.getmembers():
                p=Path(m.name)
                if p.is_absolute() or '..' in p.parts or not p.parts or p.parts[0]!='go' or m.issym() or m.islnk() or m.isdev():raise RuntimeError('Unsafe Go archive member')
            tar.extractall(temp/'unpacked')
        if not (temp/'unpacked/go/bin/go').is_file():raise RuntimeError('Go SDK missing executable')
        shutil.move(str(temp/'unpacked/go'),target)
    return str(target/'bin/go')
