import os
import subprocess
import shutil
import signal
from functools import lru_cache
from pathlib import Path, PurePosixPath

ROOT=Path(__file__).resolve().parent

@lru_cache(maxsize=512)
def wslpath(path):
    return subprocess.check_output(['wsl.exe','-d','Ubuntu','--','wslpath','-a',str(Path(path).resolve())],text=True,timeout=20).strip()

class Runtime:
    def __init__(self, mode='native'):
        self.wsl = mode == 'wsl' and os.name == 'nt'
        self.folder = 'linux' if self.wsl or os.name != 'nt' else 'windows'
        self.base=PurePosixPath('/opt/pentest-lab-tools') if self.wsl else Path('/opt/pentest-lab-tools') if self.folder=='linux' else Path(os.environ.get('PROGRAMDATA','C:/ProgramData'))/'PentestLab'/'Tools'
        self.status_path=ROOT/'data'/('install-status-'+self.folder+'.json')
    def path(self,path):
        return wslpath(path) if self.wsl else str(Path(path).resolve())
    def templates_args(self):
        template=self.base/'nuclei-templates'
        if self.wsl:
            try:
                found=subprocess.run(self.wrap(['test','-d',str(template/'http')]),timeout=8,capture_output=True).returncode==0
                return ['-t',str(template)] if found else []
            except (OSError,subprocess.SubprocessError):return []
        return ['-t',str(template)] if (template/'http').is_dir() else []
    def command(self,tool):
        if self.wsl:
            # These are Linux system paths, never Windows translations of /opt.
            names=['pd-httpx','httpx'] if tool=='httpx' else [tool]
            for name in names:
                try:
                    found=subprocess.check_output(self.wrap(['sh','-c','PATH=/usr/local/bin:/usr/bin:/bin:$PATH; command -v "$1"','lab-check',name]),text=True,timeout=8).strip()
                    if found:return [found]
                except (OSError,subprocess.SubprocessError):pass
            return None
        if tool=='dnsrecon' and (self.base/'dnsrecon/pyproject.toml').is_file():
            wrapper=self.base/'bin'/('dnsrecon.cmd' if os.name=='nt' else 'dnsrecon')
            if wrapper.is_file():return [str(wrapper)]
        if tool in ('photon','theHarvester'):
            envdir=self.base/'venvs'/tool
            py=envdir/('Scripts/python.exe' if os.name=='nt' else 'bin/python')
            if tool=='photon' and (self.base/'photon/photon.py').is_file() and py.is_file():return [str(py),str(self.base/'photon/photon.py')]
            executable=envdir/('Scripts/theHarvester.exe' if os.name=='nt' else 'bin/theHarvester')
            if tool=='theHarvester' and executable.is_file():return [str(executable)]
        suffix='.exe' if os.name=='nt' else ''
        if os.name=='nt':
            if tool in ('sqlmap','nikto'):
                script=self.base/tool/('sqlmap.py' if tool=='sqlmap' else 'program/nikto.pl')
                if script.is_file():
                    if tool=='sqlmap':return [str(self.base/'venv/Scripts/python.exe'),str(script)]
                    perl=shutil.which('perl') or str(Path(os.environ.get('SystemDrive','C:')+'/Strawberry/perl/bin/perl.exe'))
                    return [perl,str(script)]
            if tool in ('arjun','dnsrecon'):
                candidate=self.base/'venv/Scripts'/(tool+'.exe')
            else:candidate=self.base/'bin'/(tool+suffix)
            if candidate.is_file():return [str(candidate)]
        if tool=='go':
            sdks=sorted((self.base/'go-sdk').glob('go*/bin/go'),key=lambda p:tuple(int(x) for x in __import__('re').findall(r'\d+',p.parent.parent.name)),reverse=True)
            if sdks:return [str(sdks[0])]
        roots=[Path('/usr/local/bin'),Path.home()/'go/bin',Path.home()/'.local/bin']
        if os.name=='nt':roots.extend([self.base/'bin',Path(os.environ.get('ProgramFiles','C:/Program Files'))/'Nmap',Path(os.environ.get('ProgramFiles(x86)','C:/Program Files (x86)'))/'Nmap'])
        search=os.pathsep.join([*(str(p) for p in roots),os.environ.get('PATH','')])
        names=['pd-httpx','httpx'] if tool=='httpx' else [tool]
        for name in names:
            found=shutil.which(name,path=search)
            if found:return [found]
        return None
    def workdir(self,tool):
        if not self.wsl and tool=='photon' and (self.base/'photon').is_dir():return str(self.base/'photon')
        return None
    def wrap(self, args):
        if self.wsl:
            setup='umask 077; lab_tmp="$HOME/.cache/pentest-lab/tmp"; [ ! -L "$lab_tmp" ] || exit 1; mkdir -p "$lab_tmp" || exit 1; chmod 700 "$lab_tmp" || exit 1; export TMPDIR="$lab_tmp" TMP="$lab_tmp" TEMP="$lab_tmp" GOTMPDIR="$lab_tmp"; exec "$@"'
            return ['wsl.exe','-d','Ubuntu','--','sh','-c',setup,'lab-runtime',*args]
        return args

def kill_tree(proc):
    if proc.poll() is not None: return
    if os.name=='nt':
        subprocess.run(['taskkill','/PID',str(proc.pid),'/T','/F'],capture_output=True)
    else:
        try: os.killpg(proc.pid,signal.SIGTERM)
        except ProcessLookupError: pass
        try: proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try: os.killpg(proc.pid,signal.SIGKILL)
            except ProcessLookupError: pass

def prepare_wsl_group(runtime, argv, pidfile):
    if not runtime.wsl: return runtime.wrap(argv)
    # The PID file is on the shared Windows filesystem. It identifies only this
    # scan process group, so cancelling does not shut down unrelated WSL work.
    return runtime.wrap(['setsid','bash','-c','echo $$ > "$1"; shift; exec "$@"','lab-job',runtime.path(pidfile),*argv])

def stop_process(runtime, proc, pidfile):
    if runtime.wsl:
        try:
            pid=Path(pidfile).read_text().strip()
            if pid.isdigit():
                subprocess.run(runtime.wrap(['bash','-c','kill -TERM -- -"$1" 2>/dev/null; kill -KILL -- -"$1" 2>/dev/null; true','lab-stop',pid]),capture_output=True,timeout=15)
        except (OSError, subprocess.SubprocessError): pass
    kill_tree(proc)
