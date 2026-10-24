"""Exact host scope, URL normalization and tool-specific routing."""
import ipaddress
from urllib.parse import urlsplit, urlunsplit, parse_qsl

STATIC = {'.js','.mjs','.cjs','.png','.jpg','.jpeg','.gif','.svg','.webp','.ico','.css','.woff','.woff2','.ttf','.mp4','.pdf','.zip'}

def normalize(value):
    if any(c in value for c in ('\r','\n','\t')): raise ValueError('Control characters are not allowed in URLs')
    value = value.strip()
    if len(value) > 4096 or any(ord(c) < 33 for c in value) or '\\' in value:
        raise ValueError('Invalid URL')
    p = urlsplit(value)
    if p.scheme not in ('http', 'https') or not p.hostname or p.username or p.password:
        raise ValueError('Use an http:// or https:// URL without credentials')
    host = p.hostname.encode('idna').decode('ascii').lower().rstrip('.')
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not all(part and all(c.isalnum() or c == '-' for c in part) for part in host.split('.')):
            raise ValueError('Invalid hostname')
    port = p.port
    authority = '[' + host + ']' if ':' in host else host
    if port and not (p.scheme == 'http' and port == 80 or p.scheme == 'https' and port == 443):
        authority += ':' + str(port)
    return urlunsplit((p.scheme, authority, p.path or '/', p.query, ''))

def hostname(url):
    return urlsplit(normalize(url)).hostname

def origin(url):
    p = urlsplit(normalize(url))
    return urlunsplit((p.scheme,p.netloc,'/','',''))

class Scope:
    def __init__(self, seed, hosts):
        self.seed = normalize(seed)
        self.hosts = {hostname(self.seed)}
        for host in hosts:
            host = host.strip()
            if host:
                self.hosts.add(hostname(host if '://' in host else 'https://' + host))
    def allows(self, url):
        try:
            return hostname(url) in self.hosts
        except (ValueError, UnicodeError):
            return False
    def filter(self, urls):
        clean = set()
        for url in urls:
            try:
                url = normalize(url)
                if self.allows(url): clean.add(url)
            except (ValueError, UnicodeError):
                pass
        return sorted(clean)

def route(urls):
    roots, endpoints, params = set(), set(), set()
    for url in urls:
        url = normalize(url)
        roots.add(origin(url))
        p = urlsplit(url)
        if any(p.path.lower().endswith(ext) for ext in STATIC): continue
        endpoints.add(urlunsplit((p.scheme,p.netloc,p.path,'','')))
        if parse_qsl(p.query,keep_blank_values=True): params.add(url)
    return {'roots':sorted(roots),'endpoints':sorted(endpoints),'parameters':sorted(params)}


def dedupe_parameters(urls):
    """Keep one URL per origin/path/parameter-name shape, preserving first values."""
    seen=set();result=[]
    for url in urls:
        url=normalize(url);p=urlsplit(url)
        key=(p.scheme,p.netloc,p.path,tuple(sorted(k for k,v in parse_qsl(p.query,keep_blank_values=True))))
        if key not in seen:seen.add(key);result.append(url)
    return result
