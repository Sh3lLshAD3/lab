"""Explicit target types; removing schemes never removes www or authorization scope."""
from urllib.parse import urlsplit
from scope import normalize,hostname
HOST_TOOLS={'waybackurls','subfinder','theHarvester','dnsrecon','dnsx','naabu','nmap'}
URL_TOOLS={'httpx','katana','photon','dalfox','arjun','sqlmap','nuclei','nikto','ffuf'}

def target_for(tool,value):
    if tool in HOST_TOOLS:
        import ipaddress
        try:return str(ipaddress.ip_address(value.strip()))
        except ValueError:pass
        return hostname(value if '://' in value else 'https://'+value)
    if tool in URL_TOOLS:return normalize(value if '://' in value else 'https://'+value)
    raise ValueError('Tool expects local JavaScript input, not a network target')

def prepare_inputs(tool,args,stdin=None):
    args=list(args)
    flags={'subfinder':'-d','theHarvester':'-d','dnsrecon':'-d','katana':'-u','photon':'-u','arjun':'-u','sqlmap':'-u','ffuf':'-u','nikto':'-h'}
    flag=flags.get(tool)
    if flag in args:
        i=args.index(flag)+1;args[i]=target_for(tool,args[i])
    if tool=='nmap' and args:
        args[-1]=target_for(tool,args[-1])
        if ':' in args[-1] and '-6' not in args:args.insert(0,'-6')
    if tool=='dalfox' and len(args)>1 and args[0] in ('url','scan'):args[1]=target_for(tool,args[1])
    if tool=='waybackurls' and stdin:stdin='\n'.join(target_for(tool,s) for s in stdin.splitlines() if s.strip())+'\n'
    return args,stdin
