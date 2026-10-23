#!/usr/bin/env python3
"""Compatibility entry point for the unified system installer UI."""
import os
from pathlib import Path
import runpy
import sys
root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root))
os.environ['LAB_OPEN_SETUP']='1'
if __name__=='__main__':runpy.run_path(str(root/'app.py'),run_name='__main__')
