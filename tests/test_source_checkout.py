from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'setup'))
from catalog import SOURCES
from source_checkout import checkout

class SourceCheckoutTests(unittest.TestCase):
    def test_exact_requested_clone_urls(self):
        self.assertEqual(SOURCES['photon'],'https://github.com/s0md3v/Photon.git')
        self.assertEqual(SOURCES['theHarvester'],'https://github.com/laramies/theHarvester.git')
        for tool in SOURCES:
            with tempfile.TemporaryDirectory() as tmp:
                calls=[];destination=Path(tmp)/tool
                checkout(tool,destination,calls.append,read_output=lambda args:SOURCES[tool])
                self.assertEqual(calls[0],['git','clone','--depth','1',SOURCES[tool],destination])
    def test_wrong_origin_prevents_update(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination=Path(tmp);(destination/'.git').mkdir();calls=[]
            with self.assertRaisesRegex(RuntimeError,'does not match'):checkout('photon',destination,calls.append,update=True,read_output=lambda args:'https://github.com/other/project.git')
            self.assertEqual(calls,[])
    def test_nonrepository_directory_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp);(path/'keep.txt').write_text('preserve')
            with self.assertRaisesRegex(RuntimeError,'preserved'):checkout('photon',path,lambda args:None)
            self.assertEqual((path/'keep.txt').read_text(),'preserve')
    def test_matching_source_updates_without_recloning(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp);(path/'.git').mkdir();calls=[]
            checkout('theHarvester',path,calls.append,update=True,read_output=lambda args:'git@github.com:laramies/theHarvester.git')
            self.assertEqual(calls[0],['git','-C',path,'pull','--ff-only'])

if __name__=='__main__':unittest.main()
