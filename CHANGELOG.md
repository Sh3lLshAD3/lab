## 3.1.0 — Live scan monitor

- One-second status refresh with per-tool Running, Success, Failed, Timeout, Skipped and pending states.
- Active log is published before process launch; follow the current tool or inspect a previous invocation. Optional auto-scroll.
- Attempt/success/failure counts preserve earlier failures when a tool runs again; elapsed time updates during execution.
- Installation rows use running/success/failure colors alongside existing verification and progress.
- Reviewed the newly supplied recon-tools and auto-rec ZIPs for status, log and installation behavior. Existing system installation locations and disk-backed temporary storage are retained.

# Changelog

## 3.0.1

- Exposed exact Photon/theHarvester source URLs in inventory detail and installation state/logs.
- Verified repository origin before updating an existing checkout; preserved unrelated directories.
- Added tests for requested clone URLs, matching-origin updates and conflicting directories.

## 3.0.0

- Added active scan adapters for DNSx, Naabu, Photon and theHarvester.
- Retained and extended DNSRecon, Nmap and Katana workflows; all 16 tools now have installation and scan selection.
- Routed OSINT/crawl URLs and discovered web services through scoped HTTP probing before web checks.
- Added top-port, crawl-depth and OSINT-source options; full and core profiles.
- Added reconnaissance observations, candidate filtering, phase status and unique open-port counting.
- Restored per-component dependency inventory, version/path/check details, install progress, final recheck and setup TXT/JSON exports.
- Added source installations for Photon and theHarvester; uv-managed Python when required by theHarvester.
- Added report preview and application/scan version metadata; retained Word and HTML exports.
- Retained system installation, exact-host authorization, durable history, cancellation, and the disk-backed temporary-storage fix.
