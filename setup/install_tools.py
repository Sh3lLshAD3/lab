"""Shared selective, repeatable installer. No target scans run here."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from catalog import CORE, GO_MODULES, INSTALLABLE, SOURCES
from runtime import ROOT, Runtime
from inventory import probe
from system_install import publish_command
from temp_storage import configure_temp,describe_temp
from go_bootstrap import ensure_go
from source_checkout import checkout

def main():
    print(describe_temp(configure_temp()),flush=True)
    raw=os.environ.get('LAB_SELECTED_TOOLS',','.join(INSTALLABLE))
    selected=[x for x in dict.fromkeys(raw.split(',')) if x]
    if not selected or any(x not in INSTALLABLE for x in selected):raise ValueError('Invalid selected tool list')
    update=os.environ.get('LAB_UPDATE_TOOLS')=='1'
    if os.name=='nt':
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():raise RuntimeError('System installation requires an Administrator terminal')
    elif os.geteuid()!=0:raise RuntimeError('Run sudo bash setup/install-linux.sh for system installation')
    runtime=Runtime();base=runtime.base;base.mkdir(parents=True,exist_ok=True)
    (base/'bin').mkdir(exist_ok=True)
    env=os.environ.copy();env.update(PYTHONUNBUFFERED='1',GOBIN=str(base/'bin'),GOTOOLCHAIN='auto')
    started=time.time()
    status={name:{'name':name,'state':'pending','verified':False,'source':SOURCES.get(name,'')} for name in selected}
    status_path=runtime.status_path
    new_status_dir=not status_path.parent.exists()
    status_path.parent.mkdir(parents=True,exist_ok=True)
    if new_status_dir and os.name!='nt' and os.environ.get('SUDO_UID'):
        os.chown(status_path.parent,int(os.environ['SUDO_UID']),int(os.environ.get('SUDO_GID',os.environ['SUDO_UID'])))
    def save(name,state,**details):
        status[name].update(state=state,**details)
        tmp=status_path.with_suffix('.tmp');tmp.write_text(json.dumps({'updated':time.time(),'started':started,'tools':list(status.values()),'completed':sum(x['state'] in ('installed','already installed','failed') for x in status.values()),'total':len(selected)},indent=2),encoding='utf-8');tmp.replace(status_path)
        if os.name!='nt' and os.environ.get('SUDO_UID'):
            os.chown(status_path,int(os.environ['SUDO_UID']),int(os.environ.get('SUDO_GID',os.environ['SUDO_UID'])))
        print(f'[{state.upper()}] {name}',flush=True)
    def call(args):
        print('$ '+' '.join(map(str,args)),flush=True)
        subprocess.run(list(map(str,args)),env=env,check=True)
    go=None;python=None;failed=[]
    for name in selected:
        try:
            before=probe(Runtime(),name)
            if before['verified'] and not update:
                if name=='nuclei' and not (base/'nuclei-templates/http').is_dir():call([*Runtime().command('nuclei'),'-update-templates','-ud',base/'nuclei-templates'])
                save(name,'already installed',**{k:before[k] for k in ('verified','version','path','detail')});continue
            save(name,'running')
            if name in GO_MODULES:
                if go is None:
                    go=ensure_go(base/'go-sdk')
                    env['PATH']=str(Path(go).parent)+os.pathsep+env.get('PATH','')
                if name in ('katana','naabu'):env['CGO_ENABLED']='1'
                else:env['CGO_ENABLED']='0'
                call([go,'install',GO_MODULES[name]+'@latest'])
            elif name in ('arjun','sqlmap'):
                python=base/'venv'/('Scripts/python.exe' if os.name=='nt' else 'bin/python')
                if not python.is_file():call([sys.executable,'-m','venv',base/'venv'])
                if name!='sqlmap':call([python,'-m','pip','install','--no-cache-dir',*(['--upgrade'] if update else []),name])
            if name in SOURCES:
                print('[SOURCE] '+name+': '+SOURCES[name],flush=True)
                dest=checkout(name,base/name,call,update=update)
                venv=dest/'.venv' if name=='dnsrecon' else base/'venvs'/name
                tool_python=venv/('Scripts/python.exe' if os.name=='nt' else 'bin/python')
                if name in ('photon','secretfinder'):
                    if not tool_python.is_file():call([sys.executable,'-m','venv',venv])
                    call([tool_python,'-m','pip','install','--no-cache-dir','-r',dest/'requirements.txt'])
                else:
                    # uv provides the Python version required by the project's lockfile,
                    # without replacing the OS Python. All runtimes stay under /opt/ProgramData.
                    manager=base/'manager-venv'
                    manager_python=manager/('Scripts/python.exe' if os.name=='nt' else 'bin/python')
                    if not manager_python.is_file():call([sys.executable,'-m','venv',manager])
                    uv=manager/('Scripts/uv.exe' if os.name=='nt' else 'bin/uv')
                    if not uv.is_file():call([manager_python,'-m','pip','install','--no-cache-dir','uv'])
                    env['UV_PYTHON_INSTALL_DIR']=str(base/'python-runtimes')
                    env['UV_PROJECT_ENVIRONMENT']=str(venv)
                    call([uv,'sync','--project',dest,'--no-dev'])
                    if name=='dnsrecon':call([uv,'run','--project',dest,'--no-sync','dnsrecon','-h'])
            if name in ('sqlmap','nikto'):

                url='https://github.com/'+('sqlmapproject/sqlmap.git' if name=='sqlmap' else 'sullo/nikto.git')
                dest=base/name
                if (dest/'.git').is_dir():
                    if update:call(['git','-C',dest,'pull','--ff-only'])
                else:call(['git','clone','--depth','1',url,dest])
                call(['git','-C',dest,'rev-parse','HEAD'])
            if name=='nmap':
                if os.name=='nt':call(['winget','install','--id','Insecure.Nmap','--exact','--accept-source-agreements','--accept-package-agreements','--disable-interactivity'])
                else:call(([] if os.geteuid()==0 else ['sudo','-n'])+['apt-get','install','-y','nmap'])
            publish_command(name,base,env)
            check=probe(Runtime(),name)
            if not check['verified']:raise RuntimeError(check['detail'])
            if name=='nuclei':
                templates=base/'nuclei-templates'
                if update or not (templates/'http').is_dir():call([*Runtime().command('nuclei'),'-update-templates','-ud',templates])
            save(name,'installed',**{k:check[k] for k in ('verified','version','path','detail')})
        except Exception as exc:
            failed.append(name);save(name,'failed',detail=str(exc),verified=False)
    # Verify every selected tool again after all dependency changes.
    for name in selected:
        if status[name]['state']=='failed':continue
        check=probe(Runtime(),name)
        if not check['verified']:
            if name not in failed:failed.append(name)
            save(name,'failed',verified=False,detail='Final verification failed: '+check['detail'])
        else:save(name,status[name]['state'],**{k:check[k] for k in ('verified','version','path','detail')})
    print(f'[SUMMARY] {len(selected)-len(failed)}/{len(selected)} selected tools verified',flush=True)
    return 1 if failed else 0

if __name__=='__main__':
    try:sys.exit(main())
    except Exception as exc:print('[FAILED]',exc,flush=True);sys.exit(1)
