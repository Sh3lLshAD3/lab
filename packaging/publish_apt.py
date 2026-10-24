#!/usr/bin/env python3
"""Create a flat, signed APT repository from Debian packages."""
import argparse
import gzip
from pathlib import Path
import shutil
import subprocess

def build_index(packages,output):
    output=Path(output).resolve();pool=output/'pool';pool.mkdir(parents=True,exist_ok=True)
    for path in Path(packages).glob('*.deb'):shutil.copy2(path,pool/path.name)
    if not list(pool.glob('*.deb')):raise ValueError('No Debian packages')
    data=subprocess.check_output(['apt-ftparchive','packages','pool'],cwd=output)
    (output/'Packages').write_bytes(data);(output/'Packages.gz').write_bytes(gzip.compress(data,mtime=0))
    for name in ('Release','Release.gpg','InRelease'):(output/name).unlink(missing_ok=True)
    release=subprocess.check_output(['apt-ftparchive','-o','APT::FTPArchive::Release::Origin=PentestLab','-o','APT::FTPArchive::Release::Label=PentestLab','release','.'],cwd=output)
    (output/'Release').write_bytes(release)
    return output

def publish(packages,output,key):
    output=build_index(packages,output)
    common=['gpg','--batch','--yes','--pinentry-mode','loopback','--passphrase-fd','0','--local-user',key]
    import os
    secret=os.environ.get('APT_GPG_PASSPHRASE','').encode()+b'\n'
    subprocess.run(common+['--clearsign','--output','InRelease','Release'],cwd=output,input=secret,check=True)
    subprocess.run(common+['--armor','--detach-sign','--output','Release.gpg','Release'],cwd=output,input=secret,check=True)
    (output/'public-key.asc').write_bytes(subprocess.check_output(['gpg','--armor','--export',key]))
    (output/'index.html').write_text('<h1>Pentest Lab signed APT repository</h1><p>Use the public key fingerprint and installation instructions from the source repository.</p>')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--packages',required=True);p.add_argument('--output',required=True);p.add_argument('--key',required=True);a=p.parse_args();publish(a.packages,a.output,a.key)
