import copy
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import engine

class LiveStatusTests(unittest.TestCase):
    def test_log_published_and_readable_before_process_finishes(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(engine,'ROOT',Path(tmp)):
            job={'id':'live','target':'http://localhost/','scope':['localhost'],'tools':['ffuf'],'findings':[],'stages':[],'status':'running'}
            snapshots=[];worker=engine.Engine(job,lambda j:snapshots.append(copy.deepcopy(j)),threading.Event())
            with patch.object(worker.runtime,'command',return_value=[sys.executable,'-c',"import time;print('live fixture',flush=True);time.sleep(1)"]),patch.object(worker.runtime,'workdir',return_value=tmp),patch.object(engine,'prepare_wsl_group',side_effect=lambda rt,args,pid:args):
                thread=threading.Thread(target=worker.run,args=('ffuf',[]));thread.start()
                try:
                    deadline=time.monotonic()+.8
                    while time.monotonic()<deadline:
                        published=[j for j in snapshots if j['stages'][-1].get('log')]
                        if published:
                            log=Path(tmp)/'data/live'/published[-1]['stages'][-1]['log']
                            if log.exists() and 'live fixture' in log.read_text():break
                        time.sleep(.02)
                    else:self.fail('Live output not published before completion')
                    self.assertTrue(thread.is_alive());self.assertEqual(published[-1]['stages'][-1]['status'],'running')
                finally:thread.join(4)
            self.assertEqual(job['coverage']['ffuf']['successes'],1)

    def test_active_retry_does_not_hide_previous_failure(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(engine,'ROOT',Path(tmp)):
            job={'id':'retry','target':'http://localhost/','scope':['localhost'],'tools':['ffuf'],'findings':[],'stages':[{'name':'ffuf','status':'failed'},{'name':'ffuf','status':'running'}],'status':'running'}
            worker=engine.Engine(job,lambda j:None,threading.Event());worker.checkpoint()
            self.assertEqual(job['coverage']['ffuf']['state'],'running');self.assertEqual(job['coverage']['ffuf']['failures'],1)
