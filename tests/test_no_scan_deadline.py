import ast
import inspect
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from engine import Engine
class NoScanDeadlineTests(unittest.TestCase):
    def test_default_execution_has_no_deadline(self):
        self.assertIsNone(inspect.signature(Engine.run).parameters['timeout'].default)
    def test_all_pipeline_invocations_have_no_deadline(self):
        root=Path(__file__).resolve().parents[1]
        checked=0
        for filename in ['engine.py','recon.py','javascript_scan.py']:
            tree=ast.parse((root/filename).read_text())
            for node in ast.walk(tree):
                if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr=='run':
                    checked+=1
                    for keyword in node.keywords:
                        if keyword.arg=='timeout':self.assertIsNone(ast.literal_eval(keyword.value),filename)
                    for arg in node.args:
                        if isinstance(arg,ast.List):
                            self.assertFalse(any(isinstance(x,ast.Constant) and x.value in ('-maxtime','--maxtime','--time-limit') for x in arg.elts))
        self.assertGreaterEqual(checked,17)
