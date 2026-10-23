import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from temp_storage import configure_temp
import bootstrap

class TemporaryStorageTests(unittest.TestCase):
    def test_full_tmp_setting_is_replaced_for_children(self):
        with tempfile.TemporaryDirectory() as root,patch.dict(os.environ,{'TMPDIR':'/unavailable-full-tmp'}),patch.object(tempfile,'tempdir',tempfile.tempdir):
            directory=configure_temp(Path(root)/'disk-temp')
            result=subprocess.check_output([sys.executable,'-c','import tempfile; print(tempfile.gettempdir())'],text=True).strip()
            self.assertEqual(result,str(directory))
            for name in ('TMPDIR','TMP','TEMP','GOTMPDIR'):self.assertEqual(os.environ[name],str(directory))
            self.assertEqual(list(directory.iterdir()),[])
    @unittest.skipIf(os.name=='nt','Unix directory permissions')
    def test_private_permissions(self):
        with tempfile.TemporaryDirectory() as root,patch.dict(os.environ,{}),patch.object(tempfile,'tempdir',tempfile.tempdir):
            directory=configure_temp(Path(root)/'private')
            self.assertEqual(directory.stat().st_mode&0o777,0o700)
    @unittest.skipIf(os.name=='nt','Unix symlink behavior')
    def test_symlink_directory_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);(root/'real').mkdir();(root/'link').symlink_to(root/'real',target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError,'symbolic link'):configure_temp(root/'link')
    def test_bootstrap_disables_package_cache(self):
        with tempfile.TemporaryDirectory() as root,patch.object(bootstrap,'ROOT',Path(root)),patch.object(bootstrap,'configure_temp',return_value=Path(root)),patch.object(bootstrap.subprocess,'run') as run,patch.object(bootstrap.os,'execv') as launch,patch.object(bootstrap.os,'chdir'):
            bootstrap.main()
            commands=[c.args[0] for c in run.call_args_list]
            self.assertTrue(any('--no-cache-dir' in command and 'requirements.txt' in str(command) for command in commands))
            launch.assert_called_once()

if __name__=='__main__':unittest.main()
