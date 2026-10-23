from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from system_install import publish_command
from catalog import SOURCES

class DNSReconUVTests(unittest.TestCase):
    @unittest.skipIf(os.name=='nt','POSIX wrapper test')
    def test_published_command_uses_uv_and_forwards_arguments(self):
        with tempfile.TemporaryDirectory(prefix='dns lab ') as tmp:
            base=Path(tmp);(base/'bin').mkdir();uv=base/'manager-venv/bin/uv';uv.parent.mkdir(parents=True)
            uv.write_text('#!/bin/sh\nprintf "%s\\n" "$UV_PROJECT_ENVIRONMENT" "$@"\n');uv.chmod(0o755)
            publish_command('dnsrecon',base,{},base/'published')
            output=subprocess.check_output([str(base/'published/dnsrecon'),'-h'],text=True).splitlines()
            self.assertEqual(output,[str(base/'dnsrecon/.venv'),'run','--project',str(base/'dnsrecon'),'--no-sync','dnsrecon','-h'])
            self.assertEqual(SOURCES['dnsrecon'],'https://github.com/darkoperator/dnsrecon.git')
