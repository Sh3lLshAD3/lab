# Validation

Validated on 24 October 2026 with Python 3.12 on Linux. Validation uses local fixtures; no external assessment target was scanned.

## Automated tests

Run from the project directory:

```bash
python -m unittest discover -s tests -v
```

All 45 automated tests passed in the build environment. The suite covers:

- Exact Photon/theHarvester clone URLs and repository-origin validation; existing non-repository directories are preserved.

- All 16 scan adapters exercised together with fixture outputs, including Photon/Katana routing into Dalfox/SQLmap, Naabu-to-Nmap port routing, HTTP candidate ports, host-scope filtering, recon coverage and unique port counts.
- Domain-only input, version metadata, recon-option validation and setup TXT/JSON downloads.

- Exact-host scope, deceptive hosts, malformed URLs, IPv6 and URL routing.
- Representative query-shape deduplication and repeated-finding suppression.
- Full pipeline with mocked adapters, plus selected httpx/Nuclei stages executed as actual local fixture subprocesses.
- Process exit failure, timeout, cancellation, missing tools and incomplete coverage.
- Core tool selection, selective installer API and invalid JSON bodies.
- Wrong HTTPX identity rejection and cached inventory checks.
- Installer skip behavior for verified existing tools.
- Go SDK checksum rejection and rejection of archive symlinks.
- Atomic JSON persistence, revision changes, small summary responses and selected-job detail.
- A bad inherited TMPDIR is replaced for a real child Python process; private temp permissions, symlink rejection and no-cache bootstrap arguments are checked.
- System install path selection, terminal-command publication in temporary test directories, existing-file preservation, HTTPX alias separation and WSL Linux template paths.
- API access token, Host and Origin checks; single-job concurrency.
- Word report structure and XML-invalid control character sanitization.
- Portable HTML escaping of evidence.

## UI and scripts

JavaScript passes Node syntax checking. Linux launcher/setup scripts pass Bash syntax checking. A development-only JSDOM harness exercised tool checkboxes, selective installation, scan submission, scope-panel toggling, safe evidence display, retained evidence expansion, and unchanged-job detail caching. This verifies DOM behavior, not browser layout.

The Word exporter was rendered and inspected using a QA-only report fixture. No fabricated assessment result is included in the deliverable.

## Limits of validation

Windows/PowerShell execution, WSL bootstrap/reboot behavior, Linux desktop GUI rendering, real upstream installations, live scanner outputs and visual browser layout were not verified on their target platforms. The extras launcher now uses the unified setup UI. The new uv/Photon/theHarvester install paths are covered by static validation, not real installation. No real system tool installation was performed during these tests; publication tests use temporary prefixes.

Upstream tools are installed from current modules/branches. CLI flags and schemas can change. Tool verification checks that an executable responds as expected; it does not prove every scan option is supported or that the target assessment will complete. Go template/binary installation may still require OS-specific libraries or permissions.

## 3.1.0 live status validation

47 unit tests pass, including a real local fixture subprocess whose log is readable while it is still running, plus retry status aggregation. DOM tests cover active-tool output refresh even when job revision is unchanged. No external scan or real tool installation was performed. Output buffering in upstream tools may delay individual log lines; the UI polls once per second.

## 3.1.1 DNSRecon
48 unit tests pass. A local executable fixture verifies the published DNSRecon wrapper invokes uv with the dedicated environment, project path and original arguments. Actual upstream download and uv dependency synchronization were not executed.

## 3.1.2 unlimited jobs
49 unit tests pass, including real local subprocess completion and cancellation with no job deadline. UI DOM checks pass. No external scans performed.
