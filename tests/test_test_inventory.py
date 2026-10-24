import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from report_data import test_inventory
class TestInventoryTests(unittest.TestCase):
    def test_execution_download_parser_and_skipped_are_distinguished(self):
        job={'tools':['secretfinder','sqlmap'],'stages':[{'name':'secretfinder','execution_kind':'download','status':'done'},{'name':'secretfinder','execution_kind':'tool','process_started':True,'status':'done'},{'name':'sqlmap','execution_kind':'tool','process_started':False,'status':'skipped'},{'name':'sqlmap','status':'failed','detail':'parser error'}]}
        ledger=test_inventory(job);self.assertEqual(ledger['attempts'],2);self.assertEqual(ledger['completed'],1);self.assertEqual(ledger['failed'],0)
        rows={r['tool']:r for r in ledger['rows']};self.assertEqual(rows['secretfinder']['launched'],1);self.assertEqual(rows['sqlmap']['skipped'],1)
    def test_repeat_runs_and_failure_counts(self):
        job={'stages':[{'name':'dalfox','execution_kind':'tool','status':s} for s in ['done','failed','timed out','running']]}
        ledger=test_inventory(job);self.assertEqual(ledger['attempts'],4);self.assertEqual(ledger['completed'],1);self.assertEqual(ledger['failed'],2);self.assertEqual(ledger['running'],1)
    def test_legacy_unknown_does_not_invent_tests(self):
        ledger=test_inventory({'stages':[{'name':'nuclei','status':'done'}]});self.assertEqual(ledger['attempts'],0)
