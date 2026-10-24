#!/usr/bin/env python3
"""Sync apt-owned code into a private user runtime; preserve scans and environments."""
import json
import os
from pathlib import Path
import shutil
import sys

def sync(source,destination):
    source=Path(source).resolve();destination=Path(destination)
    if destination.is_symlink():raise RuntimeError('Refusing symlink runtime directory')
    destination.mkdir(parents=True,exist_ok=True,mode=0o700)
    manifest=json.loads((source/'package-files.json').read_text())
    previous=[]
    try:previous=json.loads((destination/'.installed-files.json').read_text())
    except (OSError,ValueError):pass
    for name in manifest:
        rel=Path(name)
        if rel.is_absolute() or '..' in rel.parts or rel.parts[0] in ('data','.venv','settings.json'):raise ValueError('Unsafe package manifest')
        target=destination/rel
        if any(p.is_symlink() for p in [target,*target.parents] if p!=destination.parent):raise RuntimeError('Refusing symlink runtime path')
        target.parent.mkdir(parents=True,exist_ok=True)
        if not target.exists() or target.read_bytes()!=(source/rel).read_bytes():
            import tempfile
            with tempfile.NamedTemporaryFile(dir=target.parent,delete=False) as stream:
                stream.write((source/rel).read_bytes());temp=Path(stream.name)
            temp.replace(target)
    for name in set(previous)-set(manifest):
        rel=Path(name)
        if rel.is_absolute() or '..' in rel.parts or not rel.parts or rel.parts[0] in ('data','.venv','settings.json'):continue
        target=destination/rel
        if target.is_file() and not target.is_symlink() and target.resolve().is_relative_to(destination.resolve()):target.unlink()
    (destination/'.installed-files.json').write_text(json.dumps(manifest))
    return destination
if __name__=='__main__':
    root=Path(os.environ.get('XDG_DATA_HOME',str(Path.home()/'.local/share')))/'pentest-lab/app'
    if root.is_symlink():raise RuntimeError('Refusing symlink runtime directory')
    root.mkdir(parents=True,exist_ok=True,mode=0o700)
    import fcntl
    lock=open(root/'.launcher.lock','a')
    try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:print('Pentest Lab is already running; close it before restarting.',file=sys.stderr);sys.exit(1)
    os.set_inheritable(lock.fileno(),True)
    root=sync(Path(__file__).resolve().parents[1],root)
    if sys.argv[1:2]==['--doctor']:
        os.execv(sys.executable,[sys.executable,str(root/'command_doctor.py'),*sys.argv[2:]])
    os.execv(sys.executable,[sys.executable,str(root/'bootstrap.py'),*sys.argv[1:]])
