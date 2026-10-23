import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import threading
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scope import dedupe_parameters
import inventory
import engine
from runtime import Runtime
from catalog import CHECKS

FAKE='''import sys,json
from pathlib import Path
tool=sys.argv[1];args=sys.argv[2:]
if '-version' in args:
 print('ProjectDiscovery httpx v1.2.3');raise SystemExit(0)
if tool=='httpx':
 values=Path(args[args.index('-l')+1]).read_text().splitlines()
 Path(args[args.index('-o')+1]).write_text('\\n'.join(json.dumps({'url':u,'status_code':200}) for u in values))
if tool=='nuclei':
 values=Path(args[args.index('-l')+1]).read_text().splitlines()
 Path(args[args.index('-o')+1]).write_text('\\n'.join(json.dumps({'matched-at':u,'info':{'name':'fixture','severity':'info'}}) for u in values))
'''

class EfficiencyTests(unittest.TestCase):
    def test_query_shape_deduplication(self):
        urls=['https://lab.example/a?id=1','https://lab.example/a?id=2','https://lab.example/a?id=2&sort=a','https://lab.example/a?sort=b&id=3','https://lab.example/b?id=1']
        self.assertEqual(dedupe_parameters(urls),[urls[0],urls[2],urls[4]])
    def test_inventory_cache(self):
        with patch.dict(inventory._CACHE,{},clear=True),patch.object(inventory,'probe',side_effect=lambda r,n:{'name':n,'required':False,'verified':True}) as probe:
            inventory.inspect();inventory.inspect();self.assertEqual(probe.call_count,len(CHECKS))
            inventory.inspect(refresh=True);self.assertEqual(probe.call_count,2*len(CHECKS))
    def test_real_subprocess_fixture_and_selected_pipeline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'data').mkdir();script=root/'fixture.py';script.write_text(FAKE)
            job={'id':'fixture','target':'http://localhost:3000/a?id=1','scope':['localhost'],'kind':'scan','tools':['httpx','nuclei'],'runtime':'native','limits':{'urls':20,'roots':2,'endpoints':5,'parameters':8},'created':'2026-10-23T00:00:00Z','status':'queued','findings':[],'stages':[]}
            snapshots=[]
            with patch.object(engine,'ROOT',root),patch.object(Runtime,'command',side_effect=lambda tool:[sys.executable,str(script),tool]):
                worker=engine.Engine(job,lambda x:snapshots.append(copy.deepcopy(x)),threading.Event());worker.execute()
            self.assertEqual(job['status'],'complete');self.assertEqual([s['name'] for s in job['stages']],['httpx','nuclei'])
            self.assertEqual(len(job['findings']),1);self.assertIn('dalfox',job['disabled_tools'])
            self.assertTrue((root/'data/fixture/report.docx').exists())
            self.assertTrue(all('failed' not in s['status'] for s in job['stages']))
    def test_duplicate_findings_save_once(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(engine,'ROOT',Path(tmp)):
            job={'id':'fixture','target':'http://localhost/','scope':[],'findings':[]}
            snapshots=[];worker=engine.Engine(job,lambda x:snapshots.append(1),threading.Event())
            for _ in range(50):worker.finding('test','title','http://localhost/','same')
            self.assertEqual(len(job['findings']),1);self.assertEqual(len(snapshots),1)
    def test_wrong_httpx_is_not_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            script=Path(tmp)/'wrong.py';script.write_text("print('Python HTTPX client 1.0')")
            runtime=Runtime()
            with patch.object(runtime,'command',return_value=[sys.executable,str(script)]):result=inventory.probe(runtime,'httpx')
            self.assertFalse(result['verified'])

class ApiEfficiencyTests(unittest.TestCase):
    def setUp(self):
        import app
        self.module=app;self.client=app.app.test_client();self.headers={'Host':f'127.0.0.1:{app.PORT}','X-Lab-Token':app.TOKEN}
    def test_state_omits_evidence_and_detail_uses_revision(self):
        job={'id':'fixture','kind':'scan','status':'complete','created':'2026-10-23','revision':4,'findings':[{'evidence':'PRIVATE EVIDENCE'}]}
        with patch.object(self.module,'JOBS',{'fixture':job}):
            result=self.client.get('/api/state',headers=self.headers)
            self.assertNotIn(b'PRIVATE EVIDENCE',result.data)
            detail=self.client.get('/api/job/fixture?revision=4',headers=self.headers);self.assertTrue(detail.json['unchanged'])
            detail=self.client.get('/api/job/fixture',headers=self.headers);self.assertEqual(detail.json['findings'][0]['evidence'],'PRIVATE EVIDENCE')
    def test_html_export_escapes_evidence(self):
        from html_report import render
        job={'status':'complete','created':'2026-10-23','target':'http://localhost/','findings':[{'title':'fixture','tool':'test','severity':'info','url':'http://localhost/','evidence':'<script>alert(1)</script>'}]}
        text=render(job)
        self.assertNotIn('<script>',text);self.assertIn('&lt;script&gt;',text)
    def test_atomic_job_persistence(self):
        job={'id':'fixture','kind':'scan','status':'complete','created':'2026-10-23','findings':[]}
        with tempfile.TemporaryDirectory() as tmp,patch.object(self.module,'DATA',Path(tmp)),patch.object(self.module,'JOBS',{}):
            self.module.save(job);self.module.save(job)
            data=json.loads((Path(tmp)/'fixture/job.json').read_text())
            self.assertEqual(data['revision'],2);self.assertFalse((Path(tmp)/'fixture/job.tmp').exists())
    def test_invalid_json_shapes_and_tool_selections(self):
        for body in [[],{'url':'http://localhost/','authorized':True,'tools':[{}]},{'url':'http://localhost/','authorized':True,'tools':['sqlmap']}]:
            self.assertEqual(self.client.post('/api/scan',json=body,headers=self.headers).status_code,400)
    def test_selective_install_request(self):
        platform='windows' if os.name=='nt' else 'linux'
        with tempfile.TemporaryDirectory() as tmp,patch.object(self.module,'DATA',Path(tmp)),patch.object(self.module,'JOBS',{}),patch.object(self.module,'CANCELS',{}),patch.object(self.module,'background') as bg:
            r=self.client.post('/api/setup',json={'platform':platform,'tools':['ffuf'],'update':True},headers=self.headers)
            self.assertEqual(r.status_code,202);self.assertTrue(bg.called)
            job=self.module.JOBS[r.json['id']];self.assertEqual(job['tools'],['ffuf']);self.assertTrue(job['update'])

class InstallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        setup=Path(__file__).resolve().parents[1]/'setup';sys.path.insert(0,str(setup))
        import install_tools,go_bootstrap
        cls.installer=install_tools;cls.bootstrap=go_bootstrap
    def test_verified_tools_are_not_reinstalled(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as tmp,patch.dict(os.environ,{'LAB_SELECTED_TOOLS':'ffuf','LAB_UPDATE_TOOLS':'0'}),patch.object(self.installer,'Runtime',return_value=SimpleNamespace(base=Path(tmp),status_path=Path(tmp)/'install-status.json')),patch.object(self.installer,'probe',return_value={'verified':True,'version':'1.0','path':'fixture','detail':'verified'}),patch.object(self.installer.subprocess,'run') as run:
            self.assertEqual(self.installer.main(),0);run.assert_not_called()
            data=json.loads((Path(tmp)/'install-status.json').read_text());self.assertEqual(data['tools'][0]['state'],'already installed')
    def test_go_archive_checksum_rejected(self):
        manifest=[{'stable':True,'version':'go1.99.0','files':[{'os':'linux','arch':'amd64','kind':'archive','filename':'sdk.tar.gz','sha256':'0'*64}]}]
        with tempfile.TemporaryDirectory() as tmp,patch.object(self.bootstrap.shutil,'which',return_value=None),patch.object(self.bootstrap.platform,'system',return_value='Linux'),patch.object(self.bootstrap.platform,'machine',return_value='x86_64'),patch.object(self.bootstrap.urllib.request,'urlopen',side_effect=[io.BytesIO(json.dumps(manifest).encode()),io.BytesIO(b'wrong archive')]):
            with self.assertRaisesRegex(RuntimeError,'checksum'):self.bootstrap.ensure_go(tmp)
    def test_go_archive_links_rejected(self):
        buf=io.BytesIO()
        with tarfile.open(fileobj=buf,mode='w:gz') as tar:
            member=tarfile.TarInfo('go/escape');member.type=tarfile.SYMTYPE;member.linkname='/tmp/escape';tar.addfile(member)
        data=buf.getvalue();manifest=[{'stable':True,'version':'go1.99.0','files':[{'os':'linux','arch':'amd64','kind':'archive','filename':'sdk.tar.gz','sha256':hashlib.sha256(data).hexdigest()}]}]
        with tempfile.TemporaryDirectory() as tmp,patch.object(self.bootstrap.shutil,'which',return_value=None),patch.object(self.bootstrap.platform,'system',return_value='Linux'),patch.object(self.bootstrap.platform,'machine',return_value='x86_64'),patch.object(self.bootstrap.urllib.request,'urlopen',side_effect=[io.BytesIO(json.dumps(manifest).encode()),io.BytesIO(data)]):
            with self.assertRaisesRegex(RuntimeError,'Unsafe'):self.bootstrap.ensure_go(tmp)

if __name__=='__main__':unittest.main()
