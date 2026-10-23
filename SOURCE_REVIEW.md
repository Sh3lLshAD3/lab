# Review of the supplied projects

The unified application combines the requested lab workflow with selected design ideas from `auto-rec-main.zip` and `recon-tools-main.zip`. It is a new combined project; the uploaded archives remain available as source references.

## Findings in auto rec

| Area | Observed behavior | Unified implementation |
| --- | --- | --- |
| httpx and Nuclei | Their subprocess exit codes were not checked before marking the phase done | A nonzero exit becomes failed; coverage and final status reflect incomplete stages |
| History | Scan/install jobs existed only in process dictionaries | Atomic job JSON persists status, stages and findings; unfinished jobs are marked interrupted on restart |
| Tool detection | `shutil.which` alone could mistake Python HTTPX for ProjectDiscovery httpx | Bounded CLI verification checks tool identity and reports versions and paths |
| Installation UI | Dashboard button opened a manual download modal | Checked tool selection invokes the local installer with live logs and verification |
| Polling | Scan status returned the accumulated log on every request | Summary polling excludes evidence; selected job data is fetched only when its revision changes |
| Networking | Server listened on all interfaces | Local loopback binding with access token, Host and Origin checks |
| Input | Domain-only validation excluded localhost, IPs and URL paths/ports | HTTP/HTTPS URL parsing supports local lab addresses, IPv6, ports and query strings |
| Stop and cleanup | No scan cancellation API; timed-out descendants were not explicitly handled | Stop and per-command timeout terminate the process tree or WSL job group |
| Reports | HTML export only | Word and escaped portable HTML exports |
| Nuclei | Vulnerability count came from stdout line count | JSONL matches become structured findings; warnings are not counted as vulnerabilities |

## Findings in recon tools

The Linux Tkinter installer supplied useful per-dependency states, tool version checks, a worker-to-UI queue, sequential installation, final verification and SHA-256 checking for Go SDK downloads. Those ideas informed the unified inventory and installer.

The original per-user Tkinter installer has been replaced with a compatibility launcher for the unified Setup UI. Scanner installation now uses Linux system prefixes or Windows ProgramData and machine PATH. Existing system commands are verified first; conflicting regular files are preserved.

## Tool scope in version 3

All 16 tools from the original requirement and both supplied archives are installable and scannable. Photon and theHarvester now have source installers and scan adapters. DNSx/Naabu are no longer inventory-only. See FEATURES_v3.md for an explicit feature mapping and limits.

## Efficiency choices

Verified existing tools are skipped unless Update is selected. Go SDK fallback uses a verified official archive instead of depending on an old apt Go package. Archive and crawl URLs are deduplicated by origin, path and parameter-name shape before parameter testing. This deliberately tests representative values rather than every value variant, which may reduce coverage for value-specific behavior.

Nuclei runs once for the selected origin list. The application skips external passive discovery for IP/localhost/local-test targets. Inventory checks have a 60-second cache and three verification workers. Scan tools themselves run sequentially to keep behavior predictable; this is not a benchmarked speed claim.

## Live reference check for 3.0.1

The supplied ahammed18122002-art/recon-tools and ahammed18122002-art/auto-rec GitHub pages, including raw-file URLs, could not be fetched in the build environment on 24 October 2026. No claim is made that their latest online contents were reviewed. The earlier uploaded archives were available for comparison; the official Photon and theHarvester repositories were accessible. The exact requested clone URLs are tested in the installer.
