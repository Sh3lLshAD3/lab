#!/usr/bin/env python3
"""Build an architecture-independent Debian app package without running installers."""
import argparse
import ast
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

def build(source,output,version=None):
    source=Path(source).resolve();output=Path(output).resolve();output.mkdir(parents=True,exist_ok=True)
    if version is None:
        tree=ast.parse((source/'version.py').read_text());version=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='VERSION' for t in n.targets))
    if not re.fullmatch(r'\d[0-9A-Za-z.+~:-]*',version):raise ValueError('Invalid Debian version')
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp);payload=root/'usr/share/pentest-lab';payload.mkdir(parents=True)
        files=list(source.glob('*.py'))+[source/'requirements.txt']
        for dirname in ['static','setup','wordlists','packaging']:
            files.extend(p for p in (source/dirname).rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc')
        manifest=[]
        for path in files:
            rel=path.relative_to(source);dest=payload/rel;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,dest);manifest.append(rel.as_posix())
        (payload/'package-files.json').write_text(json.dumps(manifest))
        launcher=root/'usr/bin/pentest-lab';launcher.parent.mkdir(parents=True);launcher.write_text('#!/bin/sh\nexec python3 /usr/share/pentest-lab/packaging/launch_installed.py "$@"\n');launcher.chmod(0o755)
        control=root/'DEBIAN/control';control.parent.mkdir()
        control.write_text(f'Package: pentest-lab\nVersion: {version}\nArchitecture: all\nMaintainer: Nowan <maintainers@localhost>\nDepends: python3 (>= 3.11), python3-venv, python3-pip, ca-certificates\nHomepage: https://github.com/Sh3lLshAD3/lab\nSection: utils\nPriority: optional\nDescription: Local authorized assessment lab dashboard\n Runs installed system tools and creates local evidence reports.\n')
        dest=output/f'pentest-lab_{version}_all.deb';subprocess.run(['dpkg-deb','--root-owner-group','--build',str(root),str(dest)],check=True,stdout=subprocess.DEVNULL);return dest
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--source',default=str(Path(__file__).resolve().parents[1]));p.add_argument('--output',default='dist');p.add_argument('--version');a=p.parse_args();print(build(a.source,a.output,a.version))
