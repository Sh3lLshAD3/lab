import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tool_inputs import target_for,prepare_inputs,HOST_TOOLS
from command_doctor import dalfox_profile,dalfox_arguments
ROOT=Path(__file__).resolve().parents[1]
def module(name,file):
    spec=importlib.util.spec_from_file_location(name,ROOT/'packaging'/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
class TargetAndAPTTests(unittest.TestCase):
    def test_domains_and_urls_do_not_get_mixed(self):
        url='https://www.lab.example:8443/a?q=1'
        for tool in HOST_TOOLS:self.assertEqual(target_for(tool,url),'www.lab.example')
        for tool in ['photon','sqlmap','dalfox','katana','httpx','nuclei']:self.assertEqual(target_for(tool,url),url)
        args,stdin=prepare_inputs('waybackurls',[],url+'\n');self.assertEqual(stdin,'www.lab.example\n')
        self.assertEqual(prepare_inputs('dnsrecon',['-d',url])[0],['-d','www.lab.example'])
        self.assertEqual(prepare_inputs('photon',['-u',url])[0],['-u',url])
        self.assertEqual(target_for('nmap','::1'),'::1')
        self.assertEqual(prepare_inputs('nmap',['-sT','https://[::1]/'])[0],['-6','-sT','::1'])
    def test_dalfox_cli_profiles(self):
        self.assertEqual(dalfox_profile('Commands:\n  url scan a URL\n  file scan file'),'v2')
        self.assertEqual(dalfox_profile('Commands:\n  scan Scan targets\n  server run server'),'v3')
        args=dalfox_arguments('v3','https://localhost/?q=1','result.json');self.assertEqual(args[0],'scan');self.assertIn('--workers',args);self.assertIn('--skip-discovery',args)
    def test_code_update_preserves_scans_and_settings(self):
        sync=module('apt_launcher','launch_installed.py').sync
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'source';source.mkdir();dest=Path(tmp)/'runtime';dest.mkdir();(dest/'data').mkdir();(dest/'data/history').write_text('keep');(dest/'settings.json').write_text('keep')
            (source/'app.py').write_text('first');(source/'package-files.json').write_text(json.dumps(['app.py']))
            sync(source,dest);(source/'app.py').write_text('second');sync(source,dest)
            self.assertEqual((dest/'app.py').read_text(),'second');self.assertEqual((dest/'data/history').read_text(),'keep');self.assertEqual((dest/'settings.json').read_text(),'keep')
            (source/'package-files.json').write_text(json.dumps(['../escape']))
            with self.assertRaises(ValueError):sync(source,dest)
    @unittest.skipUnless(shutil.which('dpkg-deb'),'Debian package builder required')
    def test_deb_has_launcher_but_no_scan_evidence(self):
        build=module('apt_build','build_deb.py').build
        with tempfile.TemporaryDirectory() as tmp:
            deb=build(ROOT,tmp,'4.0.0+git1')
            self.assertEqual(subprocess.check_output(['dpkg-deb','-f',str(deb),'Package'],text=True).strip(),'pentest-lab')
            extract=Path(tmp)/'extract';subprocess.run(['dpkg-deb','-x',str(deb),str(extract)],check=True)
            self.assertTrue((extract/'usr/bin/pentest-lab').is_file());self.assertFalse((extract/'usr/share/pentest-lab/data').exists())

    def test_dalfox_v3_findings_exit_is_not_failure(self):
        import engine,threading
        from unittest.mock import patch
        for profile,expected in [('v3','done'),('v2','failed')]:
            with self.subTest(profile=profile),tempfile.TemporaryDirectory() as tmp,patch.object(engine,'ROOT',Path(tmp)):
                job={'id':'exit','target':'http://localhost/','scope':['localhost'],'tools':['dalfox'],'findings':[],'stages':[],'status':'running'}
                worker=engine.Engine(job,lambda j:None,threading.Event());worker._dalfox_profile=profile
                with patch.object(worker.runtime,'command',return_value=[sys.executable,'-c','raise SystemExit(1)']),patch.object(worker.runtime,'workdir',return_value=tmp),patch.object(engine,'prepare_wsl_group',side_effect=lambda r,a,p:a):
                    worker.run('dalfox',['scan' if profile=='v3' else 'url','http://localhost/?q=1'])
                self.assertEqual(job['stages'][-1]['status'],expected)
