import sys
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import engine
import javascript_scan as js
from scope import Scope

class JavaScriptTests(unittest.TestCase):
    def test_routing_scope_extension_query_and_limit(self):
        scope=Scope('https://lab.example/',['lab.example'])
        urls=['https://lab.example/app.js?v=1','https://else.example/app.js','https://lab.example/image.png','https://lab.example/module.MJS']
        self.assertEqual(js.javascript_urls(scope,urls,1),[urls[0]])
        self.assertEqual(len(js.javascript_urls(scope,urls,10)),2)

    def test_offline_input_results_and_failed_download(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(engine,'ROOT',Path(tmp)):
            job={'id':'js','target':'http://localhost/','scope':['localhost'],'tools':['secretfinder'],'findings':[],'stages':[],'status':'running','limits':{'urls':5}}
            worker=engine.Engine(job,lambda j:None,threading.Event());calls=[]
            def run(tool,args,**kw):
                calls.append(args);self.assertTrue(Path(args[1]).is_file());self.assertEqual(args[-2:],['-o','cli'])
                log=worker.directory/'fixture.log';log.write_text('google_api\t->\tfixture-not-a-real-key\n');return log
            worker.run=run
            with patch.object(worker.runtime,'command',return_value=['fixture']),patch.object(js,'download',side_effect=[b'var x=1;',OSError('fixture network failure')]):
                js.scan(worker,['http://localhost/a.js','http://localhost/b.js'],engine.lines,engine.now)
            self.assertEqual(len(calls),1);self.assertEqual(job['findings'][0]['kind'],'candidate');self.assertEqual(job['findings'][0]['url'],'http://localhost/a.js')
            self.assertEqual(job['stages'][-1]['status'],'failed')

    def test_redirects_are_not_followed(self):
        self.assertIsNone(js.NoRedirect().redirect_request(None,None,302,'',{},'https://else.example/'))
