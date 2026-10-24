## 3.4.1 — Delete saved scans

Completed, failed, stopped and interrupted scan jobs can be permanently deleted from their result actions after an explicit UI confirmation. Removes only the selected job folder and history entry, reports, logs and downloaded evidence. Running/queued jobs and active report workers are protected. Authenticated endpoint rejects unsafe or symlink job roots. Logical file bytes removed are shown; OS free space may differ. Installed tools are unaffected.

## 3.4.0 — Test execution register

Word and HTML list all 17 test methods with recorded command attempts, completion/failure counts, candidate counts and status. New stages explicitly distinguish actual tool commands and process launches from downloads and parser events. Counts are command attempts, not payload/request/template totals. Legacy records without metadata are excluded with an explicit limitation. Word adds a finding register with stable sequential F identifiers and a wide repeated-header test table. Referenced PentestReports collection and Groundtruth summary for report organization; no third-party findings are imported.

## 3.3.0 — Evidence based report charts

Word and portable HTML now embed candidate category pie charts, actual counts and percentages, executive summaries and explicit unverified confidence. Recon observations are excluded from charts. Conservative exact finding consolidation preserves distinct evidence, URLs, titles, methods and parameters. SecretFinder match values are hidden in exports; selected labeled credentials are masked. Raw job files retain evidence. New findings record observation timestamps. No automatic manual confirmation is inferred. Added Pillow dependency. Scan scheduling remains serial; parallel execution, resume and additional validation requests are not part of this release.

## 3.2.0 — SecretFinder JavaScript checks

- Official SecretFinder git clone and requirements.txt installation into an isolated system environment.
- Seventeenth selectable tool in Setup, inventory and scans; published secretfinder command.
- Routes discovered in-scope .js/.mjs/.cjs URLs (including query strings) to downloaded local-file CLI analysis. HTTP redirects are not followed; files are limited to 8 MB. Inline JavaScript and undiscovered script URLs are not covered.
- Candidate matches appear in live results and Word/HTML reports; download errors remain visible in tool status. Secret values are retained in local logs and reports and are not validated against third-party services.
- Arjun/Nuclei unlimited job execution remains unchanged.

## 3.1.2 — Long Arjun and Nuclei scans

Removed the 300-second Arjun and 900-second Nuclei job deadlines. Both now run until exit or user Stop, without the generic 50 MB log cutoff. Request-level network timeouts remain. Logs can grow during long runs; actual failures are still reported. Existing completed jobs are not rerun or rewritten.

## 3.1.1 — DNSRecon source installation

DNSRecon now clones the official darkoperator repository and uses uv sync with its own environment at /opt/pentest-lab-tools/dnsrecon/.venv. The system command runs uv run --no-sync dnsrecon, avoiding dependency downloads during scans. Existing verified installations are preserved unless update is selected. Select DNSRecon and enable update to migrate an older installation. uv is bootstrapped through an isolated manager environment rather than piping a downloaded shell script.

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
