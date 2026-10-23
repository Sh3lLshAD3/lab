import copy
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scope import Scope, route, normalize
import engine
from engine import Engine, records
from runtime import Runtime
from report import export

class ScopeTests(unittest.TestCase):
    def test_exact_host_boundary(self):
        s=Scope('https://lab.example:8443/',['api.lab.example'])
        for u in ['https://lab.example/','http://api.lab.example/test']: self.assertTrue(s.allows(u))
        for u in ['https://evil.lab.example/','https://lab.example.evil.test/','https://lab.example@evil.test/','file:///etc/passwd','https://lab.example/\n']: self.assertFalse(s.allows(u))
    def test_normalize_and_route(self):
        self.assertEqual(normalize('HTTPS://LAB.EXAMPLE:443/a?x=1#frag'),'https://lab.example/a?x=1')
        self.assertEqual(normalize('http://[::1]:3000/'),'http://[::1]:3000/')
        r=route(['https://lab.example/a?id=1','https://lab.example/a?id=2','https://lab.example/x.png'])
        self.assertEqual(len(r['parameters']),2);self.assertEqual(len(r['endpoints']),1);self.assertEqual(len(r['roots']),1)
    def test_reject_bad_urls(self):
        for u in ['-option','ftp://lab.example/','http://lab.example:bad/','http://lab.example/\\evil','http://user:pass@lab.example/']:
            with self.assertRaises(ValueError):normalize(u)

class EngineTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.patch=patch.object(engine,'ROOT',self.root);self.patch.start()
        (self.root/'data').mkdir()
        self.job={'id':'testjob','target':'http://lab.example/a?id=1','scope':['lab.example'],'kind':'scan','runtime':'native','limits':{'urls':20,'roots':2,'endpoints':5,'parameters':8},'created':'2026-10-23T00:00:00Z','status':'queued','findings':[],'stages':[]}
        self.snapshots=[];self.event=threading.Event();self.e=Engine(self.job,lambda j:self.snapshots.append(copy.deepcopy(j)),self.event);self.e.enabled.add('dummy')
    def tearDown(self): self.patch.stop();self.temp.cleanup()
    def test_pipeline_routing_and_findings(self):
        calls=[]
        def fake(tool,args,stdin=None,timeout=600):
            calls.append((tool,args))
            self.job['stages'].append({'name':tool,'status':'done','detail':'mocked adapter fixture'})
            logfile=self.e.directory/(tool+'.log');logfile.write_text('')
            if tool=='waybackurls':logfile.write_text('http://lab.example/a?id=1\nhttps://outside.example/?x=1\nhttp://lab.example/api\n')
            if tool=='subfinder':logfile.write_text('outside.example\n')
            if tool=='httpx':
                candidates=Path(args[args.index('-l')+1]).read_text().splitlines()
                Path(args[args.index('-o')+1]).write_text('\n'.join(json.dumps({'url':u,'status_code':200}) for u in candidates))
            if tool=='dalfox':Path(args[args.index('--output')+1]).write_text(json.dumps({'poc':'http://lab.example/a?id=fixture','payload':'fixture'}))
            if tool=='ffuf':Path(args[args.index('-o')+1]).write_text(json.dumps({'results':[{'url':'http://lab.example/login','status':200,'length':35}]}))
            if tool=='arjun':Path(args[args.index('-oJ')+1]).write_text(json.dumps({args[args.index('-u')+1]:{'params':['query']}}))
            if tool=='sqlmap':logfile.write_text("Parameter: id (GET)\n    Type: boolean-based blind\n")
            if tool=='nuclei':Path(args[args.index('-o')+1]).write_text(json.dumps({'matched-at':'http://lab.example/','info':{'name':'Fixture template match','severity':'low'}}))
            if tool=='nikto':Path(args[args.index('-output')+1]).write_text(json.dumps({'vulnerabilities':[{'msg':'fixture'}]}))
            return logfile
        self.e.run=fake;self.e.execute()
        self.assertEqual(self.job['status'],'complete')
        self.assertTrue((self.e.directory/'report.docx').is_file())
        self.assertEqual(self.job['excluded_hosts'],['outside.example'])
        self.assertTrue(all('outside.example' not in str(args) for tool,args in calls))
        self.assertTrue(any(tool=='sqlmap' and 'query=1' in str(args) for tool,args in calls))
        self.assertTrue(any(tool=='dalfox' and 'query=1' in str(args) for tool,args in calls))
        self.assertEqual({f['tool'] for f in self.job['findings']},{'dalfox','ffuf','arjun','sqlmap','nuclei','nikto'})
        self.assertTrue(self.snapshots)
    def test_process_timeout_and_cancellation(self):
        with patch.object(Runtime,'command',return_value=[sys.executable,'-c','import time; time.sleep(30)']):
            self.e.run('dummy',[],timeout=.05)
        self.assertEqual(self.job['stages'][-1]['status'],'timed out')
        timer=threading.Timer(.2,self.event.set);timer.start()
        with patch.object(Runtime,'command',return_value=[sys.executable,'-c','import time; time.sleep(30)']): self.e.run('dummy',[],timeout=20)
        self.assertEqual(self.job['stages'][-1]['status'],'cancelled')
    def test_missing_tools_are_partial(self):
        with patch.object(Runtime,'command',return_value=None):self.e.execute()
        self.assertEqual(self.job['status'],'partial')
        self.assertTrue(all(s['status']=='skipped' for s in self.job['stages']))
    def test_nonzero_process_is_failed(self):
        with patch.object(Runtime,'command',return_value=[sys.executable,'-c','raise SystemExit(7)']):self.e.run('dummy',[])
        self.assertEqual(self.job['stages'][-1]['status'],'failed')
    def test_word_report_is_valid_and_sanitizes_controls(self):
        from docx import Document
        self.job['findings']=[{'tool':'test','title':'Unverified finding','severity':'info','url':self.job['target'],'evidence':'bad\x00control','recommendation':'Review'}]
        path=self.root/'sample.docx';export(self.job,path)
        doc=Document(path);text='\n'.join(p.text for p in doc.paragraphs)
        self.assertIn('badcontrol',text);self.assertIn('manual validation',text)

class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app
        cls.module=app;cls.client=app.app.test_client();cls.host=f'127.0.0.1:{app.PORT}'
        cls.headers={'X-Lab-Token':app.TOKEN,'Host':cls.host}
    def test_token_origin_and_host(self):
        self.assertEqual(self.client.get('/api/state',headers={'Host':self.host}).status_code,403)
        self.assertEqual(self.client.get('/api/state',headers=self.headers).status_code,200)
        self.assertEqual(self.client.get('/api/state',headers={**self.headers,'Origin':'https://evil.example'}).status_code,403)
        self.assertEqual(self.client.get('/api/state',headers={**self.headers,'Host':'evil.example'}).status_code,403)
    def test_invalid_scan_and_platform(self):
        self.assertEqual(self.client.post('/api/scan',json={'url':'http://localhost/'},headers=self.headers).status_code,400)
        self.assertEqual(self.client.post('/api/setup',json={'platform':'invalid'},headers=self.headers).status_code,400)
    def test_static_ui(self):
        r=self.client.get('/',headers={'Host':self.host});self.assertEqual(r.status_code,200);self.assertIn(b'Start scan',r.data)
        self.assertIn("frame-ancestors 'none'",r.headers['Content-Security-Policy']);r.close()
    def test_scan_request_and_busy(self):
        with patch.object(self.module,'background') as bg, tempfile.TemporaryDirectory() as tmp,patch.object(self.module,'DATA',Path(tmp)),patch.object(self.module,'JOBS',{}),patch.object(self.module,'CANCELS',{}):
            r=self.client.post('/api/scan',json={'url':'http://localhost:3000/','authorized':True},headers=self.headers)
            self.assertEqual(r.status_code,202);self.assertTrue(bg.called)
            job=self.module.JOBS[r.json['id']];self.assertEqual(job['limits']['urls'],60)
            r2=self.client.post('/api/scan',json={'url':'http://localhost/','authorized':True},headers=self.headers);self.assertEqual(r2.status_code,409)
            self.assertEqual(self.client.post('/api/stop/'+job['id'],json={},headers=self.headers).status_code,200)
            self.assertTrue(self.module.CANCELS[job['id']].is_set())

if __name__=='__main__': unittest.main()
