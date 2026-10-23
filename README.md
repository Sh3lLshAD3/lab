# Pentest Lab Unified 3.1.1

এই version-এ scanner tools lab folder-এর মধ্যে install হয় না। Existing verified system tools ব্যবহার হয়; missing selected tools system location-এ install হয়। Update checkbox default off থাকে।

## v3 এ নতুন কী আছে

আপনার দেওয়া auto-rec ও recon-tools project-এর tool workflows একত্রে আছে। এখন ১৬টি tool install ও scan selection-এ পাওয়া যায়। **Full recon and checks** default-এ সব নির্বাচন করে; শুধু আগের checks চাইলে **Core checks only** চাপুন। Setup-এ missing tools প্রথমে checked থাকবে; **Select all 16 tools** দিয়ে সম্পূর্ণ selection করতে পারেন।

নতুন scan stages: DNSx, Naabu, Photon, theHarvester। Nmap-এর top 100/1000 ports, crawl depth 1–3 এবং OSINT providers নির্বাচন করা যায়। Per-tool phase status, recon/candidate filter, report preview, dependency table, component details, install progress এবং TXT/JSON setup report যোগ হয়েছে।

`FEATURES_v3.md`-তে দুইটি supplied project-এর feature mapping আছে। `CHANGELOG.md`-তে version changes আছে। এটি source project; scanner binaries ZIP-এ bundled নয়।

## Full tmpfs fix

VirtualBox Kali-তে `/tmp` প্রায় 1 GB RAM-backed tmpfs হলেও মূল disk-এ জায়গা থাকতে পারে। এই version-এর launcher dependency install-এর আগেই private disk temp folder বেছে নেয়:

- Linux: `~/.cache/pentest-lab/tmp`।
- Windows: `%LocalAppData%\pentest-lab\tmp`।
- Ubuntu WSL commands: Ubuntu user-এর `~/.cache/pentest-lab/tmp`।
- Linux apt prerequisites: installation-এর জন্য `/var/tmp`-তে একটি temporary folder; normal exit হলে installer নিজের folder পরিষ্কার করে।

pip `--no-cache-dir` ব্যবহার করে; Python এবং Go build একই disk temp setting পায়। Existing `/tmp` files delete করা হয় না, VirtualBox disk বা partition বদলানো হয় না। নির্বাচিত disk-এ সত্যিই জায়গা শেষ হলে installation তখনও ব্যর্থ হবে; startup-এ temp path ও free space দেখাবে।

আগের failed install-এর পর নতুন project folder-এ শুধু চালান:

```bash
bash start-linux.sh
```

Launcher `.venv` না থাকলে তৈরি করে; থাকলে reuse করে এবং missing dependencies install করে। আপনার root prompt হলে disk temp path `/root/.cache/pentest-lab/tmp` হবে।

## কোথায় install হবে

| Component | Linux and Ubuntu WSL | Native Windows |
| --- | --- | --- |
| Terminal commands | `/usr/local/bin/` | `%ProgramData%\PentestLab\Tools\bin` added to machine PATH |
| Tool binaries and source | `/opt/pentest-lab-tools/` | `%ProgramData%\PentestLab\Tools\` |
| Python scanner dependencies | `/opt/pentest-lab-tools/venv/` | `%ProgramData%\PentestLab\Tools\venv\` |
| Nuclei templates | `/opt/pentest-lab-tools/nuclei-templates/` | `%ProgramData%\PentestLab\Tools\nuclei-templates\` |
| App dependencies only | Lab `.venv/` | Lab `.venv\` |
| Job history and logs | Lab `data/` | Lab `data\` |

Python scanner dependencies আলাদা environment-এ থাকবে, কিন্তু সেটি system location-এ। OS Python-এ global pip বা `--break-system-packages` ব্যবহার হয় না। সাধারণ terminal থেকেও commands চালানো যায়। Lab folder delete করলে system tools uninstall হবে না।

নতুন ProjectDiscovery HTTPX-এর Linux command `pd-httpx`, যাতে Python-এর `httpx` command overwrite না হয়। App স্বয়ংক্রিয়ভাবে সঠিক command বেছে নেয়। Kali-তে existing verified ProjectDiscovery `httpx` থাকলে সেটিও ব্যবহার করতে পারে। Existing real files in `/usr/local/bin` conflict করলে overwrite না করে error দেখাবে।

## Linux বা Kali তে শুরু

Python 3.11+, venv এবং apt-based distribution প্রয়োজন।

## Installation

```bash
git clone --depth 1 https://github.com/Sh3lLshAD3/lab.git lab-dev
```

```bash
bash start-linux.sh
```

Browser-এর Setup tab-এ inventory দেখুন, tools select করুন, তারপর Linux নির্বাচন করুন। Background installer password নিতে পারে না। Permission error হলে terminal-এ project directory থেকে চালান:

```bash
sudo bash setup/install-linux.sh
```

এটি default core tools system-এ install/verify করবে। Dashboard সাধারণ user হিসেবেই চালাবেন। Tool location ও verification Setup → Recheck-এ দেখা যায়।

## Windows এ শুরু

1. Python 3.11+ এবং Python Launcher install করুন।
2. ZIP extract করে `start-windows.bat` চালান।
3. Setup → Windows → Direct Windows অথবা Ubuntu WSL নির্বাচন করুন।
4. Native system installation-এর জন্য Administrator terminal থেকে launcher চালাতে হবে। Installation শেষে app বন্ধ করে সাধারণভাবে চালাতে পারেন।
5. নতুন terminal খুললে updated machine PATH পাওয়া যাবে। App নিজেও system install location খুঁজে নেয়।

Windows setup Git/Go/Perl প্রয়োজন হলে winget দিয়ে install করে। WSL-এ Linux tools Ubuntu-এর system location-এ থাকে; Windows native tools থেকে আলাদা। প্রথম WSL setup-এ Windows restart ও Ubuntu account creation লাগতে পারে। WSL target URL Ubuntu থেকে reachable হতে হবে; Windows localhost ও WSL localhost সব configuration-এ এক নয়।

## Existing tools এবং migration

Verified system tools থাকলে Update checkbox off অবস্থায় আবার install হবে না। Update on হলে selected tools-এর newer system installation ব্যবহার হবে; package-manager-owned files uninstall বা overwrite করা হবে না। User-only Go/pipx installations root installer-এর environment-এ সবসময় visible নাও হতে পারে; system-wide installation সেই ক্ষেত্রে একটি shared command যোগ করতে পারে।

পুরোনো lab-local `.tools` এই version খোঁজে না, সরায়ও না। পুরোনো app বন্ধ করুন, নতুন version-এ Setup চালান। চাইলে আগের `data/` folder copy করে history রাখুন। Python virtual environments copy/relocate করবেন না।

## Scan workflow

URL/domain → waybackurls/subfinder/theHarvester → DNSRecon/DNSx → Naabu/Nmap → scoped httpx probe → Photon/Katana → Dalfox → ffuf/Arjun → নতুন parameter URL-এ Dalfox → SQLmap → Nuclei → Nikto → report preview ও Word/HTML export।

- Core tools: subfinder, httpx, waybackurls, dalfox, ffuf, arjun, sqlmap, nuclei, nikto।
- Additional scan/install: Katana, DNSRecon, Nmap, DNSx, Naabu, Photon, theHarvester।
- Photon official source ও আলাদা Python environment-এ install হয়। theHarvester-এর source installation uv দিয়ে project runtime/dependencies তৈরি করে; OS Python replace করে না।
- `extras/run_mh_installer.sh` এখন একই unified Setup UI খোলার compatibility launcher; আলাদা user-folder installer নেই।

Scan background-এ চলে। Main window findings দেখায়; logs technical details-এ। Stop, timeout, persistent history এবং Word/HTML report আছে। Scanner session বন্ধ হলে unfinished job পরেরবার interrupted দেখাবে; automatic scan resume নেই।

## Scope এবং coverage

শুধু target ও configured exact hostnames active inputs-এ যায়। Subdomains নিজে থেকে included নয়। Scope hostname অনুযায়ী, path বা port অনুযায়ী নয়। এটি network firewall নয়; tools নিজে DNS/ancillary requests করতে পারে। Strict lab isolation প্রয়োজন হলে VM/container networking-এ enforce করুন।

Default limits: 60 URLs, 2 hosts/origins, 5 endpoints, 8 parameter URLs; crawl depth 2; top TCP ports 1000। UI থেকে সর্বোচ্চ 300, 10, 30, 30 করা যায়। একই origin/path/parameter-name shape থেকে একটি representative URL test হয়; value-specific issue miss হতে পারে। Disabled ও incomplete tool coverage report-এ থাকে।

Scan tools sequentially চলে; একটি scan বা setup একসঙ্গে চলতে পারে। Visible browser tab প্রতি দুই সেকেন্ডে ছোট summary নেয়; selected job revision বদলালে detail নেয়। Inventory cache 60 seconds। SQLmap detection level/risk 1 ব্যবহার করে; database dumping/takeover options যোগ করা নেই।

## Results এবং tests

Automated findings manual validation ছাড়া confirmed vulnerability নয়। Missing/failed/skipped checks বা zero findings target secure প্রমাণ করে না। Scan evidence-এ sensitive URLs থাকতে পারে।

```bash
python -m unittest discover -s tests -v
```

পরীক্ষার পরিধি `TESTING.md`-তে, source review `SOURCE_REVIEW.md`-তে। Actual Windows/WSL system installs ও upstream tools দিয়ে live assessment build environment-এ করা হয়নি।

## v2 থেকে migration

পুরোনো app বন্ধ করুন। নতুন ZIP আলাদা folder-এ extract করুন। চাইলে পুরোনো `data/` copy করে history রাখুন; `.venv` copy করবেন না। আগে system-এ installed tools পুনরায় download করার প্রয়োজন নেই যদি verification pass করে। নতুন folder থেকে `bash start-linux.sh` চালিয়ে Setup → Recheck করুন, missing tools install করুন। পুরোনো app ও নতুন app একসঙ্গে একই port-এ চালাবেন না।

Full profile-এ বেশি tools ও ports থাকায় সময় বেশি লাগতে পারে। Port/DNS/OSINT records observations, confirmed vulnerability নয়। কিছু provider key বা rate-limit-এর কারণে partial outcome দিতে পারে; stage log ও coverage report দেখুন।

## Photon এবং theHarvester source URLs

Installer এই exact official repositories ব্যবহার করে:

```text
https://github.com/s0md3v/Photon.git
https://github.com/laramies/theHarvester.git
```

Setup-এ Photon/theHarvester tick করে Linux install করুন। Installer clone, Python dependencies, terminal command ও verification করবে। আগে থেকেই verified থাকলে skip করবে; update চাইলে **Update selected existing tools** tick করুন। Repository origin না মিললে existing folder update/overwrite করবে না। Inventory row চাপলে Source URL দেখা যাবে।

শুধু এই দুইটি tool terminal থেকে install করতে project folder-এ চালান:

```bash
sudo env LAB_SELECTED_TOOLS=photon,theHarvester bash setup/install-linux.sh
```

এটিও system location-এ install করে এবং full `/tmp` এড়িয়ে disk temporary storage ব্যবহার করে।
