"""Bounded parsing of Nuclei statistics, never interpreted as findings."""
import json
import re
from datetime import datetime,timezone
ANSI=re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
def read_progress(path):
    try:
        with path.open('rb') as stream:
            stream.seek(max(0,path.stat().st_size-131072));text=stream.read().decode('utf-8',errors='replace')
    except OSError:return None
    waf='"template-id":"waf-detect"' in text.replace(' ','') or '"template-id":"dns-waf-detect"' in text.replace(' ','')
    for line in reversed(text.splitlines()):
        try:value=json.loads(ANSI.sub('',line))
        except ValueError:continue
        if not isinstance(value,dict) or 'template-id' in value:continue
        if not ('requests' in value and any(k in value for k in ('rps','percent','total'))):continue
        return {'waf_observed':waf,**{k:value[k] for k in ('duration','hosts','templates','requests','total','errors','rps','percent','matched') if k in value and isinstance(value[k],(int,float,str))}}
    return {'waf_observed':True} if waf else None
