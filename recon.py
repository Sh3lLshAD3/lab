"""Adapters for the reconnaissance workflows from both supplied projects."""
import ipaddress
import json
import re
from urllib.parse import urlsplit, urlunsplit
import xml.etree.ElementTree as ET

ANSI=re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')

def strings(value):
    if isinstance(value,str):yield value
    elif isinstance(value,dict):
        for item in value.values():yield from strings(item)
    elif isinstance(value,list):
        for item in value:yield from strings(item)

def normalized_host(value):
    if not isinstance(value,str):return None
    try:
        host=urlsplit(value if '://' in value else '//'+value).hostname
        return host.encode('idna').decode().lower().rstrip('.') if host else None
    except (ValueError,UnicodeError):return None

def is_public_name(host):
    try:ipaddress.ip_address(host);return False
    except ValueError:return host!='localhost' and not host.endswith(('.localhost','.local','.test'))

def passive(worker,host,read_records,read_lines):
    """Collect OSINT as evidence; never silently authorize a discovered host."""
    if not is_public_name(host):
        worker.job['passive_note']='Public archive and OSINT queries omitted for local or IP target'
        return set(),set()
    urls=set();hosts=set()
    log=worker.run('waybackurls',[],host+'\n',timeout=None)
    if log:urls.update(worker.scope.filter(read_lines(log)))
    log=worker.run('subfinder',['-d',host,'-silent'],timeout=None)
    if log:
        for line in read_lines(log):
            name=normalized_host(line.strip())
            if name and re.fullmatch(r'[A-Za-z0-9.-]+',line.strip()):hosts.add(name)
    if 'theHarvester' in worker.enabled:
        output=worker.directory/'harvester'
        sources=','.join(worker.job.get('options',{}).get('harvester_sources',['crtsh','otx']))
        log=worker.run('theHarvester',['-d',host,'-b',sources,'-l','100','-f',worker.rp(output)],timeout=None)
        evidence=[]
        for path in (output.with_suffix('.json'),output.with_suffix('.jsonl')):
            for obj in read_records(path):
                for value in strings(obj):
                    if value.startswith(('http://','https://')):urls.add(value)
                    candidate=normalized_host(value)
                    if candidate and (candidate==host or candidate.endswith('.'+host)):hosts.add(candidate)
                evidence.append(json.dumps(obj,ensure_ascii=True))
        if not evidence and log:
            text=ANSI.sub('', '\n'.join(read_lines(log)))
            # Older versions may export different schemas; keep bounded raw evidence.
            evidence=[text[-6000:]] if text.strip() else []
        if evidence:worker.finding('theHarvester','Passive OSINT observations',worker.scope.seed,'\n'.join(evidence)[:6000])
    if 'dnsrecon' in worker.enabled:
        output=worker.directory/'dnsrecon.json'
        log=worker.run('dnsrecon',['-d',host,'-j',worker.rp(output)],timeout=None)
        values=read_records(output)
        if values:worker.finding('dnsrecon','DNS profile',worker.scope.seed,json.dumps(values,ensure_ascii=True)[:6000])
        elif log:
            text=ANSI.sub('', '\n'.join(read_lines(log)))
            if text.strip():worker.finding('dnsrecon','DNS profile output',worker.scope.seed,text[-6000:])
    return urls,hosts

def dns_and_ports(worker,urls,read_records,read_lines):
    """Restrict DNS and port inputs to explicitly scoped hosts and root limits."""
    hosts=sorted({urlsplit(u).hostname for u in urls})[:worker.job['limits']['roots']]
    inputs=worker.file('recon-hosts.txt',hosts)
    if 'dnsx' in worker.enabled:
        output=worker.directory/'dnsx.jsonl'
        worker.run('dnsx',['-l',worker.rp(inputs),'-a','-aaaa','-cname','-mx','-ns','-json','-silent','-rl','3','-o',worker.rp(output)],timeout=None)
        for record in read_records(output):
            if not isinstance(record,dict):continue
            host=normalized_host(record.get('host',''))
            if host in hosts:
                url=next(u for u in urls if urlsplit(u).hostname==host)
                worker.finding('dnsx','Resolved DNS records',url,json.dumps(record,ensure_ascii=True))
    ports={host:set() for host in hosts};web_ports={host:set() for host in hosts}
    port_records={}
    def add_port(host,port,source):
        key=(host,port)
        port_records.setdefault(key,{'host':host,'port':port,'sources':[]})
        if source not in port_records[key]['sources']:port_records[key]['sources'].append(source)
    budget=worker.job.get('options',{}).get('top_ports',1000)
    if 'naabu' in worker.enabled:
        output=worker.directory/'naabu.jsonl'
        worker.run('naabu',['-list',worker.rp(inputs),'-scan-type','c','-top-ports',str(budget),'-rate','10','-c','2','-retries','1','-json','-silent','-o',worker.rp(output)],timeout=None)
        for record in read_records(output):
            if not isinstance(record,dict):continue
            host=normalized_host(record.get('host') or record.get('ip',''))
            try:port=int(record.get('port',0))
            except (TypeError,ValueError):continue
            if host not in ports or not 1<=port<=65535:continue
            ports[host].add(port);add_port(host,port,'naabu')
            if port in (80,443,3000,5000,5001,8000,8008,8080,8443,8888,9000,9443):web_ports[host].add(port)
            url=next(u for u in urls if urlsplit(u).hostname==host)
            worker.finding('naabu','Open TCP port',url,f'{port}/tcp; '+json.dumps(record,ensure_ascii=True))
    if 'nmap' in worker.enabled:
        for index,host in enumerate(hosts):
            output=worker.directory/f'nmap-{index}.xml'
            selected=sorted(ports[host])
            flags=['-p',','.join(map(str,selected))] if selected else ['--top-ports',str(budget)]
            worker.run('nmap',['-sT','-sV',*flags,'--max-rate','10','-oX',worker.rp(output),host],timeout=None)
            if not output.is_file():continue
            try:
                for port in ET.parse(output).findall('.//port'):
                    state=port.find('state');service=port.find('service')
                    if state is not None and state.get('state')=='open':
                        url=next(u for u in urls if urlsplit(u).hostname==host)
                        number=int(port.get('portid','0'))
                        if 1<=number<=65535:
                            add_port(host,number,'nmap')
                            if service is not None and ('http' in service.get('name','') or service.get('tunnel')=='ssl'):web_ports[host].add(number)
                        worker.finding('nmap','Open network service',url,ET.tostring(port,encoding='unicode'))
            except ET.ParseError:worker.parse_warning('nmap','Malformed XML; inspect raw evidence')
    worker.job['port_records']=list(port_records.values())
    expanded=list(urls)
    for host,values in web_ports.items():
        for port in sorted(values):
            authority='['+host+']' if ':' in host else host
            scheme='https' if port in (443,8443,9443) else 'http'
            expanded.append(f'{scheme}://{authority}:{port}/')
    return list(dict.fromkeys(expanded))[:worker.job['limits']['urls']]

def crawl(worker,live,roots,read_lines):
    extra=[];depth=str(worker.job.get('options',{}).get('crawl_depth',2))
    for index,root in enumerate(roots):
        if worker.cancel.is_set():break
        if 'katana' in worker.enabled:
            output=worker.directory/f'katana-{index}.txt'
            worker.run('katana',['-u',root,'-d',depth,'-fs','fqdn','-dr','-rl','3','-c','1','-duc','-silent','-o',worker.rp(output)],timeout=None)
            extra.extend(read_lines(output))
        if 'photon' in worker.enabled:
            output=worker.directory/f'photon-{index}'
            worker.run('photon',['-u',root,'-l',depth,'-t','1','-d','0.5','--timeout','10','--only-urls','-o',worker.rp(output)],timeout=None)
            if output.is_dir():
                for file in output.rglob('*.txt'):
                    if file.stat().st_size<5_000_000:extra.extend(read_lines(file))
    return [u for u in worker.scope.filter(extra) if u not in set(live)][:worker.job['limits']['urls']]
