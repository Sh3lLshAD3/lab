# Command and target review for 4.0.0

The user repository at https://github.com/Sh3lLshAD3/lab was cloned read-only (2e3759c); its engine matches the supplied 3.5.1 base. No remote code was pushed.

| Tool | Input used by the lab | Review |
|---|---|---|
| waybackurls | hostname through stdin | Preserves www; archive discovery only |
| subfinder | hostname via -d | Official domain input |
| theHarvester | hostname via -d | OSINT providers remain selected |
| DNSRecon | hostname via -d | Official git/uv installer retained |
| dnsx | hostname/IP list | No URL schemes, ports or paths in host file |
| naabu | hostname/IP list | Connect scan; explicit rate limit |
| Nmap | hostname/IP | No http(s) URL input |
| httpx | full URL list | Scheme, explicit port, path and query retained |
| Katana | root URL | Depth and scope remain bounded |
| Photon | root URL | Official Python source confirms float delay; only-urls retained |
| SecretFinder | downloaded local JS file | Scope-checked download; no external key validation |
| Dalfox | parameter URL | Detects url/v2 versus scan/v3 help syntax; uses correct worker/mining flags; v3 exit 1 means findings, not command failure |
| ffuf | root URL with FUZZ path | JSON output and calibration retained |
| Arjun | endpoint URL | GET discovery; JSON output |
| SQLmap | parameter URL | Explicit GET params, diagnostic traffic; no extraction flags |
| Nuclei | root URL list | JSON findings and live stats; no total timeout |
| Nikto | root URL | JSON output; no total maxtime |

`tool_inputs.py` enforces target types at the subprocess boundary. Host conversion strips scheme, credentials are rejected, and www is never silently removed. Full web URLs retain http versus https, port, path and query. Scope filtering remains separate and is never broadened by normalization.

Use `pentest-lab --doctor --output command-check.json` after APT installation, or `python3 command_doctor.py --output command-check.json` in the ZIP/clone version. This reads local help/version output and checks required documented flags without scanning any target. Missing flags or verification failures need attention; a passed help check is not a successful vulnerability scan. Scanners are not bundled into the APT app package; update them separately in Setup.

## Primary sources consulted

- https://docs.projectdiscovery.io/opensource/subfinder/usage
- https://docs.projectdiscovery.io/opensource/httpx/usage
- https://docs.projectdiscovery.io/opensource/dnsx/usage
- https://docs.projectdiscovery.io/opensource/naabu/usage
- https://docs.projectdiscovery.io/opensource/katana/usage
- https://nmap.org/book/man-target-specification.html
- https://www.kali.org/tools/photon/
- https://raw.githubusercontent.com/s0md3v/Photon/master/photon.py
- https://raw.githubusercontent.com/tomnomnom/waybackurls/master/main.go
- https://github.com/s0md3v/Arjun/wiki/Usage
- https://github.com/sqlmapproject/sqlmap/wiki/Usage
- https://dalfox.hahwul.com/reference/cli/
- https://dalfox.hahwul.com/guide/output/
- https://raw.githubusercontent.com/ffuf/ffuf/master/README.md
- Previously supplied Nuclei/SQLmap installed help and official SecretFinder/DNSRecon source review.

Some raw GitHub web fetches failed; the target repository was subsequently accessed with git and selected official raw files with urllib. Actual upstream installations and live vulnerability scans were not performed. No automated suite can guarantee a vulnerable result or cover all vulnerabilities.
