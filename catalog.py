"""Shared tool catalogue for inventory, installation and scan selection."""
CORE=('subfinder','httpx','waybackurls','dalfox','ffuf','arjun','sqlmap','nuclei','nikto')
GO_MODULES={
 'subfinder':'github.com/projectdiscovery/subfinder/v2/cmd/subfinder',
 'httpx':'github.com/projectdiscovery/httpx/cmd/httpx',
 'waybackurls':'github.com/tomnomnom/waybackurls',
 'dalfox':'github.com/hahwul/dalfox/v2',
 'ffuf':'github.com/ffuf/ffuf/v2',
 'nuclei':'github.com/projectdiscovery/nuclei/v3/cmd/nuclei',
 'katana':'github.com/projectdiscovery/katana/cmd/katana',
 'dnsx':'github.com/projectdiscovery/dnsx/cmd/dnsx',
 'naabu':'github.com/projectdiscovery/naabu/v2/cmd/naabu',
}
CHECKS={
 'subfinder':['-version'],'httpx':['-version'],'waybackurls':['-h'],
 'dalfox':['version'],'ffuf':['-V'],'arjun':['-h'],'sqlmap':['--version'],
 'nuclei':['-version'],'nikto':['-Version'],'katana':['-version'],
 'dnsx':['-version'],'naabu':['-version'],'dnsrecon':['-h'],
 'nmap':['--version'],'photon':['-h'],'theHarvester':['-h'],
}
OPTIONAL=tuple(name for name in CHECKS if name not in CORE)
SCANNABLE=CORE+('katana','dnsrecon','nmap','dnsx','naabu','photon','theHarvester')
INSTALLABLE=SCANNABLE

SOURCES={'photon':'https://github.com/s0md3v/Photon.git','theHarvester':'https://github.com/laramies/theHarvester.git'}
PHASES={name:phase for phase,names in {
 'DNS and passive discovery':('subfinder','waybackurls','dnsx','dnsrecon','theHarvester'),
 'Ports and services':('naabu','nmap'),
 'Web probing and crawling':('httpx','katana','photon'),
 'Parameters and paths':('ffuf','arjun'),
 'Vulnerability checks':('dalfox','sqlmap','nuclei','nikto'),
}.items() for name in names}
