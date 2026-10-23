"""Publish selected commands outside the application folder."""
import os
from pathlib import Path
from catalog import GO_MODULES

def publish_command(name,base,env,bin_directory=None):
    if os.name=='nt':
        bindir=base/'bin'
        if name=='photon':command='"'+str(base/'venvs/photon/Scripts/python.exe')+'" "'+str(base/'photon/photon.py')+'"'
        elif name=='theHarvester':command='"'+str(base/'venvs/theHarvester/Scripts/theHarvester.exe')+'"'
        elif name in ('arjun','dnsrecon'):
            command='"'+str(base/'venv/Scripts'/(name+'.exe'))+'"'
        elif name=='sqlmap':command='"'+str(base/'venv/Scripts/python.exe')+'" "'+str(base/'sqlmap/sqlmap.py')+'"'
        elif name=='nikto':command='perl "'+str(base/'nikto/program/nikto.pl')+'"'
        else:command=None
        if command:(bindir/(name+'.cmd')).write_text('@echo off\n'+command+' %*\n',encoding='utf-8')
        import winreg
        keypath=r'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,keypath,0,winreg.KEY_READ|winreg.KEY_WRITE) as key:
            current,_=winreg.QueryValueEx(key,'Path')
            if str(bindir).casefold() not in [p.casefold().rstrip('\\') for p in current.split(';')]:
                winreg.SetValueEx(key,'Path',0,winreg.REG_EXPAND_SZ,current.rstrip(';')+';'+str(bindir))
        env['PATH']=str(bindir)+os.pathsep+env.get('PATH','')
        try:
            import ctypes
            ctypes.windll.user32.SendMessageTimeoutW(0xffff,0x001A,0,'Environment',2,3000,None)
        except (AttributeError,OSError):pass
        return
    link=Path(bin_directory or '/usr/local/bin')/('pd-httpx' if name=='httpx' else name)
    if name in GO_MODULES:target=base/'bin'/name
    elif name in ('arjun','dnsrecon'):target=base/'venv/bin'/name
    elif name=='photon':target=base/'photon/photon.py'
    elif name=='theHarvester':target=base/'venvs/theHarvester/bin/theHarvester'
    elif name=='sqlmap':target=base/'sqlmap/sqlmap.py'
    elif name=='nikto':target=base/'nikto/program/nikto.pl'
    else:return
    link.parent.mkdir(parents=True,exist_ok=True)
    # Preserve unrelated commands instead of silently overwriting package files.
    if link.exists() and not link.is_symlink():
        raise RuntimeError(f'{link} is already a real file. Existing file was preserved; choose how to resolve the conflict manually.')
    if link.is_symlink():link.unlink()
    if name in ('sqlmap','nikto','photon'):
        import shlex
        interpreter=str(base/'venvs/photon/bin/python') if name=='photon' else str(base/'venv/bin/python') if name=='sqlmap' else '/usr/bin/perl'
        wrapper=base/'bin'/name
        wrapper.write_text('#!/bin/sh\n'+('cd '+shlex.quote(str(base/'photon'))+' || exit 1\n' if name=='photon' else '')+'exec '+shlex.quote(interpreter)+' '+shlex.quote(str(target))+' "$@"\n')
        wrapper.chmod(0o755);target=wrapper
    link.symlink_to(target)
