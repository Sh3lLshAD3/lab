from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import app

class DeleteScanTests(unittest.TestCase):
    def setUp(self):
        self.client=app.app.test_client();self.headers={'Host':f'127.0.0.1:{app.PORT}','X-Lab-Token':app.TOKEN}
    def test_removes_only_selected_scan_and_clears_history(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(app,'DATA',Path(tmp)),patch.object(app,'JOBS',{'old':{'kind':'scan','status':'complete'}}),patch.object(app,'CANCELS',{}):
            folder=Path(tmp)/'old';folder.mkdir();(folder/'scan.log').write_bytes(b'12345');other=Path(tmp)/'other';other.mkdir();(other/'keep').write_text('keep')
            self.assertEqual(self.client.post('/api/delete-scan/old',json={},headers=self.headers).status_code,400)
            result=self.client.post('/api/delete-scan/old',json={'confirm':True},headers=self.headers)
            self.assertEqual(result.status_code,200);self.assertEqual(result.json['deleted_bytes'],5);self.assertFalse(folder.exists());self.assertNotIn('old',app.JOBS);self.assertTrue((other/'keep').exists())
    def test_running_and_report_worker_cannot_be_deleted(self):
        for status,workers in [('running',set()),('complete',{'old'})]:
            with self.subTest(status=status),patch.object(app,'JOBS',{'old':{'kind':'scan','status':status}}),patch.object(app,'WORKERS',workers):
                self.assertEqual(self.client.post('/api/delete-scan/old',json={'confirm':True},headers=self.headers).status_code,409)
    def test_symlink_folder_cannot_delete_external_files(self):
        with tempfile.TemporaryDirectory() as tmp,tempfile.TemporaryDirectory() as outside,patch.object(app,'DATA',Path(tmp)),patch.object(app,'JOBS',{'old':{'kind':'scan','status':'complete'}}):
            (Path(outside)/'keep').write_text('keep');(Path(tmp)/'old').symlink_to(outside,target_is_directory=True)
            self.assertEqual(self.client.post('/api/delete-scan/old',json={'confirm':True},headers=self.headers).status_code,400);self.assertTrue((Path(outside)/'keep').exists())
    def test_requires_token_and_rejects_setup(self):
        self.assertEqual(self.client.post('/api/delete-scan/old',json={'confirm':True},headers={'Host':f'127.0.0.1:{app.PORT}'}).status_code,403)
        with patch.object(app,'JOBS',{'old':{'kind':'setup','status':'complete'}}):
            self.assertEqual(self.client.post('/api/delete-scan/old',json={'confirm':True},headers=self.headers).status_code,404)
