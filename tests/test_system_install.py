import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from runtime import Runtime,ROOT
from system_install import publish_command

@unittest.skipIf(os.name=='nt','Linux publication behavior')
class SystemInstallTests(unittest.TestCase):
    def test_install_location_is_outside_lab(self):
        runtime=Runtime()
        self.assertEqual(runtime.base,Path('/opt/pentest-lab-tools'))
        self.assertFalse(runtime.base.is_relative_to(ROOT))
    def test_publish_binary_as_terminal_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp)/'opt';(base/'bin').mkdir(parents=True)
            tool=base/'bin/ffuf';tool.write_text('#!/bin/sh\nprintf installed');tool.chmod(0o755)
            bindir=Path(tmp)/'usr/local/bin'
            publish_command('ffuf',base,{},bindir)
            self.assertTrue((bindir/'ffuf').is_symlink())
            self.assertEqual(subprocess.check_output([str(bindir/'ffuf')],text=True),'installed')
    def test_python_httpx_name_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp)/'opt';(base/'bin').mkdir(parents=True);(base/'bin/httpx').write_text('fixture')
            bindir=Path(tmp)/'bin';bindir.mkdir();(bindir/'httpx').write_text('existing client')
            publish_command('httpx',base,{},bindir)
            self.assertEqual((bindir/'httpx').read_text(),'existing client')
            self.assertEqual((bindir/'pd-httpx').resolve(),base/'bin/httpx')
    def test_existing_regular_command_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp)/'opt';(base/'bin').mkdir(parents=True)
            bindir=Path(tmp)/'bin';bindir.mkdir();(bindir/'ffuf').write_text('existing')
            with self.assertRaisesRegex(RuntimeError,'preserved'):publish_command('ffuf',base,{},bindir)
            self.assertEqual((bindir/'ffuf').read_text(),'existing')
    def test_wsl_uses_linux_paths_for_templates(self):
        runtime=Runtime();runtime.wsl=True
        with patch('runtime.subprocess.run') as run:
            run.return_value.returncode=0
            self.assertEqual(runtime.templates_args(),['-t','/opt/pentest-lab-tools/nuclei-templates'])
            self.assertEqual(run.call_args.args[0][-1],'/opt/pentest-lab-tools/nuclei-templates/http')

if __name__=='__main__':unittest.main()
