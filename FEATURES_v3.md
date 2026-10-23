# Version 3 feature mapping

This release adds all tool names present in both supplied archives to the lab's selectable scan and installation workflows. It implements the workflows configured in those projects, not every possible option offered by each upstream CLI. The Google-inspired lab interface remains the main interface; equivalent installer features use a web table instead of the original Tkinter window.

## Scanner features from auto rec

| Supplied feature | Version 3 implementation |
| --- | --- |
| Bare-domain input | Accepted and normalized to HTTPS; explicit HTTP URLs, localhost, IPs and ports remain supported |
| DNS profiling | DNSRecon JSON/raw evidence and DNSx DNS records |
| Subdomain enumeration | Subfinder discoveries with explicit host-scope filtering |
| Apex always probed | The entered seed URL is retained before limits |
| Live host probing | ProjectDiscovery httpx identity check and JSONL probing |
| Nmap service scan | TCP connect/service scan; selectable top 100 or 1000 ports |
| Passive OSINT | theHarvester with crtsh/otx or crtsh/certspotter providers |
| Photon web crawl | Bounded crawl with internal URL routing into httpx and later checks |
| Arjun parameters | Structured GET parameters feed Dalfox and SQLmap |
| Nuclei vulnerability checks | Batched JSONL results with status and evidence |
| Pipeline status and logs | Tool phase chips, raw log detail and durable stage status |
| Read and download HTML report | In-app report preview and portable HTML download |
| Tool download links | Official guides for every tool, plus selected installation |

## Installer features from recon tools

| Supplied feature | Version 3 implementation |
| --- | --- |
| DNSRecon, Subfinder, httpx, Nmap, Katana, Arjun, DNSx, Naabu, Nuclei | All included as installable and scannable tools |
| Expandable system dependency inventory | Separate expandable component table with APT package versions and purposes |
| Already installed status | Existing verified tools skipped unless update is selected |
| Per-component final check | Tool verification plus dependency package checks and Tkinter import check |
| Version and executable detail | Select a row to inspect command, path and verification output |
| Sequential install steps | Checked selection, running states, progress and cancellation |
| Go SDK download and SHA verification | Official manifest, cached SDK, download messages, SHA-256 verification and safe extraction |
| Recheck | Refreshes versions, tool identity and dependencies |
| Final setup report | TXT and JSON downloads for completed/partial/failed setup jobs |
| Separate background worker | Installer/scan process work stays outside UI request handling |

## Complete tool list

| Tool | Pipeline role | Installation method |
| --- | --- | --- |
| subfinder | Passive subdomains | Go module |
| waybackurls | Archived URLs | Go module |
| httpx | Live HTTP probe | Go module; Linux command alias pd-httpx |
| dnsrecon | DNS profile | Python environment |
| dnsx | DNS records | Go module |
| theHarvester | Passive OSINT | Official checkout with uv-managed environment |
| naabu | Bounded TCP port discovery | Go module |
| nmap | Port/service verification | OS package / winget |
| photon | Web crawling | Official checkout with isolated Python environment |
| katana | Web crawling | Go module |
| arjun | GET parameter discovery | Python environment |
| ffuf | Path discovery | Go module |
| dalfox | XSS candidates | Go module |
| sqlmap | SQL injection detection | Official checkout |
| nuclei | Template matches | Go module and shared templates |
| nikto | Server configuration observations | Official checkout and Perl |

## Routing and limits

OSINT/subdomain discoveries never grant scan permission automatically. DNSx and Naabu inputs come from the exact authorized host set, capped by the host/root limit. When Naabu finds ports, Nmap can inspect only those ports; otherwise Nmap uses the selected top-port budget. Common web ports and HTTP services discovered by Nmap feed HTTP probing. Crawler URLs are filtered and probed before parameter and vulnerability stages.

Some recon stages can run even without a working HTTP service. Web-dependent stages are skipped when probing produces no live URL. Local/IP targets omit public archive/OSINT queries. Every report includes selected, omitted, failed and inapplicable tool coverage.

## Limits of parity and verification

The original decorative binary-rain canvas, developer contact panel and original Tkinter layout are not duplicated; their functional workflows are integrated into the lab UI. Upstream CLI switches beyond the supplied presets, provider API-key editing, unattended OS reboots, and arbitrary OS/driver installations are not implemented.

A tool may need network access, provider credentials, Npcap/libpcap or a newer runtime. TheHarvester's source install uses uv to choose the Python runtime required by its project; that runtime is installed outside the lab. Existing verified installations can be reused without that download.

Validation uses local fixtures and DOM interaction checks. It does not certify current upstream installations, live findings, visual browser layout or Windows/WSL execution. See TESTING.md.
