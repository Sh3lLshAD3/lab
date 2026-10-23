"""Use a private cache directory instead of a small RAM-backed /tmp mount."""
import os
from pathlib import Path
import shutil
import tempfile

def configure_temp(directory=None):
    if directory is None:
        if os.name=='nt':
            cache=Path(os.environ.get('LOCALAPPDATA',str(Path.home()/'AppData/Local')))
        else:cache=Path.home()/'.cache'
        directory=cache/'pentest-lab'/'tmp'
    directory=Path(directory).absolute()
    directory.mkdir(mode=0o700,parents=True,exist_ok=True)
    if directory.is_symlink():raise RuntimeError('Temporary directory must not be a symbolic link: '+str(directory))
    if os.name!='nt':
        if directory.stat().st_uid!=os.geteuid():raise RuntimeError('Temporary directory belongs to another user: '+str(directory))
        directory.chmod(0o700)
    with tempfile.NamedTemporaryFile(dir=directory,prefix='write-check-'):pass
    for name in ('TMPDIR','TEMP','TMP','GOTMPDIR'):os.environ[name]=str(directory)
    # Python caches the chosen directory; update it for an already-running process.
    tempfile.tempdir=str(directory)
    return directory

def describe_temp(directory):
    free=shutil.disk_usage(directory).free/(1024**3)
    return f'Temporary storage: {directory} ({free:.1f} GiB free)'
