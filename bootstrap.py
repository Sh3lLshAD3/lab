"""Create/reuse the app environment with temporary files on the user's disk."""
import os
from pathlib import Path
import subprocess
import sys
from temp_storage import configure_temp,describe_temp

ROOT=Path(__file__).resolve().parent

def main():
    if sys.version_info<(3,11):
        print('Python 3.11 or newer is required.',file=sys.stderr);return 1
    os.chdir(ROOT)
    temporary=configure_temp();print(describe_temp(temporary),flush=True)
    python=ROOT/'.venv'/('Scripts/python.exe' if os.name=='nt' else 'bin/python')
    if not python.is_file():subprocess.run([sys.executable,'-m','venv',str(ROOT/'.venv')],check=True)
    # Retry incomplete installations safely. Already satisfied packages are reused.
    subprocess.run([str(python),'-m','pip','install','--no-cache-dir','-r',str(ROOT/'requirements.txt')],check=True)
    os.execv(str(python),[str(python),str(ROOT/'app.py')])

if __name__=='__main__':
    try:sys.exit(main())
    except (OSError,RuntimeError,subprocess.CalledProcessError) as exc:
        print(f'Lab startup failed: {exc}',file=sys.stderr)
        print('Existing files and /tmp were preserved. Check the temporary-storage path above and available disk space.',file=sys.stderr)
        sys.exit(1)
