import copy
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from catalog import SCANNABLE,INSTALLABLE
from engine import Engine
import engine
from version import VERSION

class ReconV3Tests(unittest.TestCase):
    def test_all_sixteen_tools_are_scannable_and_installable(self):
        self.assertEqual(len(SCANNABLE),16);self.assertEqual(set(SCANNABLE),set(INSTALLABLE))
    def test_complete_recon_fixture_routes_outputs(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(engine,'ROOT',Path(tmp)):
            job={'id':'v3','status':'queued','kind':'scan','created':'2026-10-24','target':'https://lab.example/a?id=1','scope':['lab.example'],'tools':list(SCANNABLE),'runtime':'native','limits':{'urls':30,'roots':2,'parameters':12,'endpoints':8},'options':{'crawl_depth':2,'top_ports':1000,'harvester_sources':['crtsh','otx']},'stages':[],'findings':[]}
            calls=[];worker=Engine(job,lambda x:None,threading.Event())
            def output(args,flag,payload):
                path=Path(args[args.index(flag)+1]);path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(payload))
            def run(tool,args,stdin=None,timeout=600):
                if tool not in worker.enabled:return None
                calls.append((tool,args));job['stages'].append({'name':tool,'status':'done','detail':'Fixture only'})
                log=worker.directory/(tool+'.log');log.write_text('')
                if tool=='waybackurls':log.write_text('https://lab.example/a?id=2\nhttps://outside.example/a?id=1\n')
                if tool=='subfinder':log.write_text('unauthorized.lab.example\n')
                if tool=='theHarvester':Path(args[args.index('-f')+1]+'.json').write_text(json.dumps({'hosts':['unauthorized.lab.example'],'urls':['https://lab.example/from-osint?term=1']}))
                if tool=='dnsrecon':output(args,'-j',[{'name':'lab.example','type':'A','address':'127.0.0.1'}])
                if tool=='dnsx':output(args,'-o',{'host':'lab.example','a':['127.0.0.1']})
                if tool=='naabu':output(args,'-o',{'host':'lab.example','port':8443})
                if tool=='nmap':
                    path=Path(args[args.index('-oX')+1]);path.write_text('<nmaprun><host><ports><port protocol="tcp" portid="8443"><state state="open"/><service name="https"/></port></ports></host></nmaprun>')
                if tool=='httpx':
                    urls=Path(args[args.index('-l')+1]).read_text().splitlines()
                    Path(args[args.index('-o')+1]).write_text('\n'.join(json.dumps({'url':url,'status_code':200}) for url in urls))
                if tool=='katana':Path(args[args.index('-o')+1]).write_text('https://lab.example/katana?q=1\nhttps://outside.example/evil?q=1\n')
                if tool=='photon':
                    folder=Path(args[args.index('-o')+1]);folder.mkdir();(folder/'internal.txt').write_text('https://lab.example/photon?search=1\nhttps://outside.example/photon?x=1\n')
                if tool=='dalfox':output(args,'--output',{'poc':'fixture','payload':'fixture'})
                if tool=='ffuf':output(args,'-o',{'results':[]})
                if tool=='arjun':output(args,'-oJ',{})
                if tool=='nuclei':output(args,'-o',{'matched-at':'https://lab.example/','info':{'name':'Fixture match','severity':'info'}})
                if tool=='nikto':output(args,'-output',{'vulnerabilities':[]})
                return log
            worker.run=run;worker.execute()
            self.assertEqual(job['status'],'complete');self.assertEqual(job['version'],VERSION)
            self.assertEqual({name for name,args in calls},set(SCANNABLE))
            self.assertTrue(any(name=='dalfox' and 'https://lab.example/photon?search=1' in args for name,args in calls))
            self.assertTrue(any(name=='sqlmap' and 'https://lab.example/katana?q=1' in args for name,args in calls))
            self.assertTrue(any(name=='nmap' and '-p' in args and '8443' in args for name,args in calls))
            self.assertIn('https://lab.example:8443/',(worker.directory/'candidates.txt').read_text())
            self.assertTrue(all('outside.example' not in str(args) and 'unauthorized.lab.example' not in str(args) for name,args in calls))
            self.assertEqual(job['summary']['open_ports'],1)
            self.assertTrue(any(f['tool']=='theHarvester' and f['kind']=='observation' for f in job['findings']))
            self.assertTrue(all(item['state']=='done' for item in job['coverage'].values()))
    def test_recon_runs_without_web_listener(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(engine,'ROOT',Path(tmp)):
            job={'id':'no-web','status':'queued','kind':'scan','created':'2026-10-24','target':'http://localhost:3333/','scope':['localhost'],'tools':['httpx','naabu'],'limits':{'urls':20,'roots':1,'parameters':2,'endpoints':2},'stages':[],'findings':[]}
            worker=Engine(job,lambda x:None,threading.Event());calls=[]
            def run(tool,args,stdin=None,timeout=600):
                if tool not in worker.enabled:return None
                calls.append(tool);job['stages'].append({'name':tool,'status':'done'})
            worker.run=run;worker.execute()
            self.assertIn('naabu',calls);self.assertEqual(job['status'],'partial')
            self.assertNotIn('theHarvester',calls)
    def test_selected_noneligible_tool_coverage_explains_omission(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(engine,'ROOT',Path(tmp)):
            job={'id':'local','status':'complete','target':'http://localhost/','scope':[],'tools':['httpx','theHarvester'],'stages':[],'findings':[]}
            worker=Engine(job,lambda x:None,threading.Event());worker.checkpoint()
            self.assertEqual(job['coverage']['theHarvester']['state'],'not applicable')

class V3ApiTests(unittest.TestCase):
    def setUp(self):
        import app
        self.app=app;self.client=app.app.test_client();self.headers={'Host':f'127.0.0.1:{app.PORT}','X-Lab-Token':app.TOKEN}
    def test_version_and_invalid_recon_options(self):
        self.assertEqual(self.client.get('/api/state',headers=self.headers).json['version'],VERSION)
        for options in [{'top_ports':65535},{'harvester_sources':['unknown']},[]]:
            result=self.client.post('/api/scan',headers=self.headers,json={'url':'http://localhost/','authorized':True,'options':options})
            self.assertEqual(result.status_code,400)
    def test_domain_input_is_supported(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(self.app,'DATA',Path(tmp)),patch.object(self.app,'JOBS',{}),patch.object(self.app,'CANCELS',{}),patch.object(self.app,'background'):
            response=self.client.post('/api/scan',headers=self.headers,json={'url':'lab.example','authorized':True,'tools':list(SCANNABLE)})
            self.assertEqual(response.status_code,202)
            self.assertEqual(self.app.JOBS[response.json['id']]['target'],'https://lab.example/')
    def test_setup_report_exports_inventory(self):
        job={'id':'fixture','kind':'setup','version':VERSION,'status':'complete','created':'2026-10-24','tools':['dnsx'],'inventory':{'dependencies':[{'name':'Git','verified':True,'version':'fixture','detail':'Local fixture'}],'tools':[{'name':'dnsx','verified':True,'version':'fixture'}]}}
        with patch.object(self.app,'JOBS',{'fixture':job}):
            txt=self.client.get('/api/setup-report/fixture',headers=self.headers);self.assertEqual(txt.status_code,200);self.assertIn(VERSION.encode(),txt.data);self.assertIn(b'DEPENDENCIES',txt.data)
            report=self.client.get('/api/setup-report/fixture?format=json',headers=self.headers);self.assertEqual(report.json['tools'],['dnsx'])

if __name__=='__main__':unittest.main()
