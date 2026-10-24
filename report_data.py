"""Shared report aggregation; preserves source evidence without confirming candidates."""
from collections import Counter
from copy import deepcopy
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
import re

NOTICE='Percentages describe unique automated candidates, not vulnerability probability or percentage of the site affected. Recon observations are excluded. All candidates require manual validation.'

def category(f):
    title=f.get('title','').lower();tool=f.get('tool','')
    if tool=='sqlmap' or 'sql injection' in title:return 'SQL Injection'
    if tool=='dalfox' or 'cross site scripting' in title or 'cross-site scripting' in title:return 'XSS'
    if tool=='secretfinder':return 'Exposed Secrets'
    if tool=='nikto' or 'misconfiguration' in title or 'configuration issue' in title:return 'Misconfiguration'
    return 'Other'

def redact(value):
    text=str(value)
    text=re.sub(r'(?i)((?:password|passwd|pwd|api[_-]?key|access[_-]?token|secret|authorization|cookie)\s*[=:]\s*)([^\s&,;]+)',r'\1[REDACTED]',text)
    text=re.sub(r'(?i)(bearer\s+)[A-Za-z0-9_.+/=-]+',r'\1[REDACTED]',text)
    return text

def summarize(job):
    groups={};observations=[]
    for raw in job.get('findings',[]):
        f=deepcopy(raw)
        if f.get('kind')=='observation':observations.append(f);continue
        cat=category(f)
        # Conservative: distinct template titles, URLs, methods and parameters remain distinct.
        key=(cat,f.get('title','').strip().casefold(),f.get('url',''),f.get('method','GET'),f.get('parameter',''),str(f.get('evidence','')).strip())
        if key not in groups:
            f.update(category=cat,confidence='Unverified',sources=[],evidence_items=[]);groups[key]=f
        item=groups[key]
        if f.get('tool') not in item['sources']:item['sources'].append(f.get('tool','Unknown'))
        evidence=f.get('evidence','')
        if evidence not in item['evidence_items']:item['evidence_items'].append(evidence)
    findings=list(groups.values());counts=Counter(f['category'] for f in findings)
    total=len(findings)
    distribution=[{'category':cat,'count':n,'percent':100*n/total} for cat,n in sorted(counts.items())]
    return {'findings':findings,'observations':observations,'distribution':distribution,'total':total,'raw_candidates':sum(f.get('kind')!='observation' for f in job.get('findings',[])),'notice':NOTICE}

def chart_png(summary):
    from PIL import Image,ImageDraw,ImageFont
    from io import BytesIO
    image=Image.new('RGB',(1200,600),'white');draw=ImageDraw.Draw(image)
    try:font=ImageFont.truetype('DejaVuSans.ttf',25)
    except OSError:font=ImageFont.load_default(size=25)
    draw.text((30,20),'Automated candidate distribution',font=font,fill='#152238')
    colors=['#2563eb','#db2777','#d97706','#059669','#7c3aed'];start=-90
    if not summary['total']:draw.text((80,250),'No vulnerability candidates recorded',font=font,fill='#445066')
    else:
        for i,row in enumerate(summary['distribution']):
            end=start+360*row['count']/summary['total'];draw.pieslice((40,85,500,545),start,end,fill=colors[i%len(colors)]);start=end
            y=125+i*72;draw.rectangle((550,y,575,y+25),fill=colors[i%len(colors)])
            draw.text((595,y),row['category']+'  '+str(row['count'])+'  ('+format(row['percent'],'.1f')+'%)',font=font,fill='#152238')
    out=BytesIO();image.save(out,format='PNG');return out.getvalue()

def public_evidence(f):
    if f.get('category')=='Exposed Secrets':return '[REDACTED secret match] Raw evidence is retained in the local job folder.'
    return redact('\n\n'.join(f.get('evidence_items',[f.get('evidence','')]))[:12000])

TEST_METHODS={
 'sqlmap':'SQL injection checks','dalfox':'Cross site scripting checks',
 'nuclei':'Template based vulnerability checks','nikto':'Server configuration checks',
 'secretfinder':'JavaScript secret pattern checks','arjun':'GET parameter discovery',
 'ffuf':'Web path discovery','httpx':'HTTP availability checks',
 'katana':'Web crawling','photon':'Web crawling','waybackurls':'Archive URL discovery',
 'subfinder':'Subdomain discovery','theHarvester':'Passive OSINT discovery',
 'dnsrecon':'DNS enumeration','dnsx':'DNS resolution','naabu':'TCP port discovery','nmap':'Port and service detection'}
COUNT_NOTICE='Counts below are recorded tool command attempts, not payloads, HTTP requests, Nuclei templates or confirmed vulnerabilities. Download and parser stages are excluded. Target counts are unavailable unless explicitly recorded. A completed command does not prove every internal test completed. Older stages without execution metadata are excluded; their test counts cannot be verified.'

def test_inventory(job):
    from catalog import SCANNABLE
    summary=summarize(job);rows=[]
    selected=set(job.get('tools',[]))
    for tool in SCANNABLE:
        stages=[s for s in job.get('stages',[]) if s.get('name')==tool]
        attempts=[s for s in stages if s.get('execution_kind')=='tool' or ('execution_kind' not in s and s.get('command'))]
        counts=Counter(s.get('status','unknown') for s in attempts)
        launches=sum(s.get('process_started') is True for s in attempts)
        completed=counts['done'];failed=sum(counts[k] for k in ('failed','timed out','cancelled','interrupted'))
        cov=job.get('coverage',{}).get(tool,{})
        state=cov.get('state') or (stages[-1].get('status') if stages else 'not run' if tool in selected else 'not selected')
        findings=sum(tool in f['sources'] for f in summary['findings'])
        rows.append({'tool':tool,'test':TEST_METHODS.get(tool,'Other checks'),'attempts':len(attempts),'completed':completed,'failed':failed,'running':counts['running'],'launched':launches,'candidates':findings,'state':state,'skipped':sum(s.get('status')=='skipped' for s in stages)})
    return {'rows':rows,'attempts':sum(r['attempts'] for r in rows),'completed':sum(r['completed'] for r in rows),'failed':sum(r['failed'] for r in rows),'running':sum(r['running'] for r in rows),'notice':COUNT_NOTICE}
