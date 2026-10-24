"""Read-only executable/flag diagnostics. Never receives a scan target."""
import argparse
import json
import re
import subprocess
from inventory import probe
from runtime import Runtime,kill_tree
from catalog import SCANNABLE
from tool_inputs import HOST_TOOLS

def help_text(runtime,tool,subcommand=None):
    command=runtime.command(tool)
    if not command:return ''
    proc=None
    try:
        args=command+([subcommand] if subcommand else [])+(['-hh'] if tool=='sqlmap' else ['--help'] if tool in ('dalfox','secretfinder') else ['-h'])
        proc=subprocess.Popen(runtime.wrap(args),stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=__import__('os').name!='nt')
        try:out,_=proc.communicate(timeout=15)
        except subprocess.TimeoutExpired:kill_tree(proc);proc.communicate();return ''
        return out.decode('utf-8',errors='replace')[:200000]
    except OSError:return ''

def dalfox_profile(text):
    return 'v3' if re.search(r'^\s*scan\s',text,re.M) and not re.search(r'^\s*url\s',text,re.M) else 'v2'

def dalfox_arguments(profile,url,output):
    if profile=='v3':return ['scan',url,'--format','json','--silence','--workers','1','--delay','350','--skip-mining','--skip-discovery','--output',output]
    return ['url',url,'--format','json','--silence','--worker','1','--delay','350','--skip-mining-all','--output',output]

REQUIRED={
 'subfinder':['-d','-silent'],'httpx':['-l','-json','-rl'],'waybackurls':[],
 'dalfox':['--format','--output'],'ffuf':['-w','-u','-of'],'arjun':['-u','-m','-oJ'],
 'sqlmap':['-u','--batch','--output-dir'],'nuclei':['-l','-jsonl','-stats','-sj'],
 'nikto':['-h','-Format','-output'],'katana':['-u','-d','-o'],'dnsx':['-l','-json'],
 'naabu':['-list','-scan-type'],'dnsrecon':['-d','-j'],'nmap':['-sT','-sV','-oX'],
 'photon':['-u','--only-urls','--timeout'],'theHarvester':['-d','-b','-f'],
 'secretfinder':['-i','-o']}

def inspect_commands(runtime):
    rows=[]
    for tool in SCANNABLE:
        result=probe(runtime,tool);text=help_text(runtime,tool)
        if tool=='dalfox':text+='\n'+help_text(runtime,tool,'scan' if dalfox_profile(text)=='v3' else 'url')
        missing=[flag for flag in REQUIRED[tool] if not (re.search(r'(?<![\w-])'+re.escape(flag)+r'(?![\w-])',text) or (tool=='nmap' and re.search('/'+re.escape(flag.lstrip('-'))+r'(?![\w])',text)))]
        result.update(input_type='hostname/IP' if tool in HOST_TOOLS else 'local JavaScript file' if tool=='secretfinder' else 'HTTP(S) URL',missing_documented_flags=missing,command_compatible=result['verified'] and bool(text) and not missing)
        rows.append(result)
    return rows
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',choices=['native','wsl'],default='native');p.add_argument('--output');a=p.parse_args()
    rows=inspect_commands(Runtime(a.runtime));data=json.dumps(rows,indent=2)
    if a.output:__import__('pathlib').Path(a.output).write_text(data,encoding='utf-8')
    print(data)
