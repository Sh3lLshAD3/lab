import sys
from pathlib import Path
import tempfile
import unittest
from copy import deepcopy
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from report_data import summarize,chart_png,public_evidence
from report import export
from html_report import render

class ReportDataTests(unittest.TestCase):
    def fixture(self):
        findings=[]
        for tool,count,title in [('sqlmap',3,'Potential SQL injection'),('dalfox',4,'Potential cross site scripting'),('nikto',3,'Potential server configuration issue')]:
            for i in range(count):findings.append({'tool':tool,'title':title,'kind':'candidate','severity':'unverified','url':f'http://localhost/{tool}/{i}?id=1','evidence':'fixture only'})
        return {'id':'fixture','status':'complete','target':'http://localhost/','created':'2026-10-24','stages':[],'findings':findings}
    def test_percentages_exclude_observations_and_duplicates(self):
        job=self.fixture();job['findings']+=[deepcopy(job['findings'][0]),{'tool':'ffuf','kind':'observation','title':'Path','url':'http://localhost/','evidence':'fixture'}]
        before=deepcopy(job);s=summarize(job)
        self.assertEqual(s['total'],10);self.assertEqual({x['category']:x['percent'] for x in s['distribution']},{'SQL Injection':30,'XSS':40,'Misconfiguration':30})
        self.assertEqual(job,before);self.assertTrue(all(f['confidence']=='Unverified' for f in s['findings']))
    def test_no_findings_has_no_fabricated_percentages(self):
        s=summarize({'findings':[]});self.assertEqual(s['distribution'],[]);self.assertTrue(chart_png(s).startswith(b'\x89PNG'))
    def test_both_exports_embed_chart_and_mask_secret(self):
        job=self.fixture();job['findings'].append({'tool':'secretfinder','kind':'candidate','title':'Possible secret','url':'http://localhost/app.js','severity':'unverified','evidence':'DO_NOT_PUBLISH_THIS_KEY'})
        html=render(job);self.assertIn('data:image/png;base64,',html);self.assertNotIn('DO_NOT_PUBLISH_THIS_KEY',html)
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'report.docx';export(job,path)
            from zipfile import ZipFile
            with ZipFile(path) as z:
                self.assertTrue(any(n.startswith('word/media/') for n in z.namelist()));self.assertNotIn(b'DO_NOT_PUBLISH_THIS_KEY',z.read('word/document.xml'))

    def test_distinct_evidence_is_not_merged(self):
        job=self.fixture();other=deepcopy(job['findings'][0]);other['evidence']='different injection evidence';job['findings'].append(other)
        self.assertEqual(summarize(job)['total'],11)
