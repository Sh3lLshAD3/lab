"""Per-component OS dependency inventory from the supplied installer."""
import os
import re
import subprocess
from runtime import Runtime

PACKAGES={
 'Git':('git','Source checkout'), 'Curl':('curl','HTTPS downloads'),
 'Wget':('wget','File downloads'), 'CA certificates':('ca-certificates','TLS trust'),
 'Python 3':('python3','Python tools'), 'Python pip':('python3-pip','Package installation'),
 'Python venv':('python3-venv','Isolated Python tool environments'),
 'pipx':('pipx','Optional Python CLI compatibility'),
 'libpcap-dev':('libpcap-dev','Naabu build headers'),
 'build-essential':('build-essential','C compiler and build tools'),
 'jq':('jq','JSON shell workflows'), 'Tkinter':('python3-tk','Python desktop compatibility'),
}

def inspect_dependencies(runtime):
    rows=[]
    if runtime.folder=='linux':
        cmd=runtime.wrap(['dpkg-query','-W','-f=${binary:Package}\t${Version}\t${Status}\n',*[p for p,purpose in PACKAGES.values()]])
        found={}
        try:
            result=subprocess.run(cmd,capture_output=True,text=True,timeout=15)
            for line in result.stdout.splitlines():
                fields=line.split('\t',2)
                if len(fields)==3:found[fields[0].split(':')[0]]=(fields[1],fields[2]=='install ok installed')
            for name,(package,purpose) in PACKAGES.items():
                version,ok=found.get(package,('Not installed',False))
                if name=='Tkinter' and ok:
                    imported=subprocess.run(runtime.wrap(['python3','-c','import tkinter; print(tkinter.TkVersion)']),capture_output=True,text=True,timeout=10)
                    ok=imported.returncode==0
                    if not ok:version+=' (python3 import failed)'
                rows.append({'name':name,'package':package,'purpose':purpose,'verified':ok,'installed':ok,'version':version,'detail':f'{package}: '+('installed' if ok else 'not installed'),'command':['dpkg-query','-W',package]})
        except (OSError,subprocess.SubprocessError) as exc:
            rows=[{'name':name,'package':p,'purpose':purpose,'verified':False,'installed':False,'version':'Unknown','detail':str(exc)} for name,(p,purpose) in PACKAGES.items()]
    else:
        for name,tool,args in [('Git','git',['--version']),('Python 3','python',['--version']),('Perl','perl',['-v'])]:
            command=runtime.command(tool)
            try:
                result=subprocess.run(runtime.wrap(command+args),capture_output=True,text=True,timeout=10) if command else None
                text=(result.stdout+result.stderr).strip() if result else 'Not installed'
                rows.append({'name':name,'package':tool,'purpose':'Windows runtime dependency','verified':bool(result and result.returncode==0),'installed':bool(command),'version':text.splitlines()[0] if text else 'Unknown','detail':text[:4000],'command':(command or [])+args})
            except (OSError,subprocess.SubprocessError) as exc:rows.append({'name':name,'verified':False,'version':'Unknown','detail':str(exc)})
    command=runtime.command('go')
    try:
        result=subprocess.run(runtime.wrap(command+['version']),capture_output=True,text=True,timeout=10) if command else None
        text=(result.stdout+result.stderr).strip() if result else 'Not installed'
        rows.append({'name':'Go runtime','package':'go','purpose':'Builds Go tools','verified':bool(result and result.returncode==0),'installed':bool(command),'version':text,'detail':text,'path':command[0] if command else '', 'command':(command or [])+['version']})
    except (OSError,subprocess.SubprocessError) as exc:rows.append({'name':'Go runtime','verified':False,'version':'Unknown','detail':str(exc)})
    return rows
