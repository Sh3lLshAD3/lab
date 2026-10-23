"""Checkout only the configured DNSRecon/Photon/theHarvester upstream repositories."""
from pathlib import Path
import subprocess
from urllib.parse import urlsplit
from catalog import SOURCES

def repository_key(url):
    url=url.strip()
    if url.startswith('git@github.com:'):url='https://github.com/'+url[len('git@github.com:'):]
    parts=urlsplit(url)
    if parts.hostname!='github.com' or parts.scheme not in ('https','ssh'):return None
    return parts.path.strip('/').removesuffix('.git').casefold()

def checkout(name,destination,call,update=False,read_output=None):
    expected=SOURCES[name];destination=Path(destination)
    if destination.exists() and not (destination/'.git').is_dir():
        raise RuntimeError(f'{destination} exists but is not a Git checkout. It was preserved; move it aside before retrying.')
    existed=(destination/'.git').is_dir()
    if not existed:call(['git','clone','--depth','1',expected,destination])
    if read_output is None:
        read_output=lambda args:subprocess.check_output(list(map(str,args)),text=True,timeout=30).strip()
    origin=read_output(['git','-C',destination,'remote','get-url','origin'])
    if repository_key(origin)!=repository_key(expected):
        raise RuntimeError(f'{name} source does not match the configured official repository; no update was performed.')
    if existed and update:call(['git','-C',destination,'pull','--ff-only'])
    call(['git','-C',destination,'rev-parse','HEAD'])
    return destination
