import json
import sys
import threading
import tempfile
import time
from pathlib import Path
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import engine
from live_progress import read_progress

class ProgressTests(unittest.TestCase):
    def test_statistics_not_confused_with_waf_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'out.log';p.write_text(json.dumps({'template-id':'waf-detect','requests':2})+'\n'+json.dumps({'requests':'42','total':'100','errors':'3','rps':'5','percent':'42'})+'\npartial')
            result=read_progress(p);self.assertEqual(result['requests'],'42');self.assertTrue(result['waf_observed'])
    def test_skip_process_keeps_job_cancel_unset(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(engine,'ROOT',Path(tmp)):
            job={'id':'skip','target':'http://localhost/','scope':['localhost'],'tools':['arjun'],'findings':[],'stages':[],'status':'running'}
            event=threading.Event();worker=engine.Engine(job,lambda j:None,event)
            with patch.object(worker.runtime,'command',return_value=[sys.executable,'-c','import time;time.sleep(30)']),patch.object(worker.runtime,'workdir',return_value=tmp),patch.object(engine,'prepare_wsl_group',side_effect=lambda r,a,p:a):
                t=threading.Thread(target=worker.run,args=('arjun',[]),kwargs={'timeout':None});t.start()
                try:
                    end=time.monotonic()+3
                    while worker.active_log is None and time.monotonic()<end:time.sleep(.02)
                    self.assertIsNotNone(worker.active_log);worker.skip_log=worker.active_log
                finally:t.join(5)
            self.assertFalse(t.is_alive());self.assertFalse(event.is_set());self.assertEqual(job['stages'][-1]['status'],'skipped');self.assertIn('arjun',worker.skipped_tools)
    def test_log_paging_and_skip_token_guard(self):
        import app
        headers={'Host':f'127.0.0.1:{app.PORT}','X-Lab-Token':app.TOKEN};client=app.app.test_client()
        with tempfile.TemporaryDirectory() as tmp,patch.object(app,'DATA',Path(tmp)),patch.object(app,'JOBS',{'fixture':{'kind':'scan'}}):
            folder=Path(tmp)/'fixture';folder.mkdir();(folder/'x.log').write_text('0123456789')
            r=client.get('/api/log/fixture/x.log?offset=2&limit=4',headers=headers);self.assertEqual(r.json['text'],'2345');self.assertEqual(r.json['next_offset'],6)
            self.assertEqual(client.get('/api/log/fixture/x.log?offset=bad',headers=headers).status_code,400)
        class Worker:active_log='002-nuclei.log';skip_log=None
        worker=Worker()
        with patch.object(app,'ENGINES',{'fixture':worker}):
            self.assertEqual(client.post('/api/skip-tool/fixture',json={'log':'old.log'},headers=headers).status_code,409)
            self.assertEqual(client.post('/api/skip-tool/fixture',json={'log':worker.active_log},headers=headers).status_code,200);self.assertEqual(worker.skip_log,worker.active_log)
