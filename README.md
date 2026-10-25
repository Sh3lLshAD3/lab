# Pentest Lab Unified 4.0.2

**Developed by Nowan**

নিজের lab বা অনুমোদিত assessment-এর জন্য local browser dashboard। System scanner tools চালানো, live command/output দেখা এবং Word/HTML report তৈরি করা যায়।

Source repository: [Sh3lLshAD3/lab](https://github.com/Sh3lLshAD3/lab)

## Linux বা Kali installation — Git clone

Python **3.11 বা নতুন**, Git ও Python venv প্রয়োজন। প্রথমবার prerequisites install করুন:

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip ca-certificates
python3 --version
```

তারপর project download ও চালু করুন:

```bash
git clone --depth 1 https://github.com/Sh3lLshAD3/lab.git lab-dev
cd lab-dev
bash start-linux.sh
```

`lab-dev` folder আগে থেকেই থাকলে আবার clone করবেন না; নিচের Git update পদ্ধতি ব্যবহার করুন। Python version 3.11-এর কম হলে আগে supported Python install করতে হবে।

Launcher app-এর `.venv` তৈরি/reuse করে এবং `requirements.txt` থেকে dependencies install করে। Terminal-এ দেওয়া local browser link খুলুন।

### Scanner tools install

Dashboard-এ **Setup → tools select → Linux** চাপুন। Privileged installation-এর জন্য প্রয়োজন হলে একই terminal থেকে:

```bash
cd ~/lab-dev
sudo bash setup/install-linux.sh
```

এটি default-এ সব ১৭টি selectable scanner install/verify করার চেষ্টা করে। শুধু নির্বাচিত tools install করতে:

```bash
sudo env LAB_SELECTED_TOOLS=photon,dnsrecon,secretfinder bash setup/install-linux.sh
```

Scanner tools system location-এ থাকে; app-এর `.venv` শুধু app dependencies-এর জন্য। Verified existing tools update option বন্ধ থাকলে reuse হয়।

## প্রতিবার app চালানো

Git clone version-এর জন্য:

```bash
cd ~/lab-dev
bash start-linux.sh
```

অন্য directory-তে clone করলে আপনার আসল path ব্যবহার করুন। Browser বন্ধ করলেই background process বন্ধ হয় না; app বন্ধ করতে terminal-এ `Ctrl+C` দিন। চলমান scan আগে UI-এর **Stop** দিয়ে শেষ করুন।

## Git দিয়ে app update — clone installation-এর জন্য

আগে চলমান scan Stop করে app-এর terminal-এ `Ctrl+C` দিন। তারপর:

```bash
cd ~/lab-dev
git status --short
git pull --ff-only
bash start-linux.sh
```

`git pull` GitHub-এ থাকা নতুন code নিয়ে আসে। Launcher নতুন app dependency থাকলে install করে। এই command নিজে GitHub-এ code upload করে না।

**Local changes-এর কারণে update ব্যর্থ হলে থামুন এবং পরিবর্তন review/backup করুন।** `git reset --hard` বা `git clean` চালানোর প্রয়োজন নেই। সাধারণ Git update scan-এর ignored `data/` ও `settings.json` রাখে, তবে গুরুত্বপূর্ণ report-এর আলাদা backup রাখা ভালো। Clone installation-এ `apt upgrade` দিয়ে app-এর source code update হয় না।

## Installed scanner tools update

App update এবং scanner update আলাদা। Dashboard-এ **Setup → tools select → Update selected existing tools → Linux** ব্যবহার করুন। Terminal বিকল্প:

```bash
cd ~/lab-dev
sudo env LAB_UPDATE_TOOLS=1 bash setup/install-linux.sh
```

শুধু নির্দিষ্ট tools update করতে:

```bash
sudo env LAB_SELECTED_TOOLS=nuclei,sqlmap LAB_UPDATE_TOOLS=1 bash setup/install-linux.sh
```

Installer verified system installation, official sources ও Nuclei templates পরিচালনা করে। Package-manager-owned executable-এর সঙ্গে conflict হলে log দেখুন; installer সেটি নির্বিচারে overwrite করে না।

## APT দিয়ে installation ও update — একবার repository setup প্রয়োজন

**GitHub-এ file upload বা Git clone করলেই APT repository তৈরি হয় না।** APT ব্যবহার করতে maintainer-এর signing key, successful GitHub Actions build ও Pages deployment প্রয়োজন; তারপর client-এ source একবার যোগ করতে হবে।

বিস্তারিত: [packaging/APT_SETUP.md](packaging/APT_SETUP.md)। এই README repository live আছে বা signing setup সম্পন্ন হয়েছে—এমন দাবি করছে না।

### Maintainer হিসেবে একবার setup

1. `.github/workflows/apt.yml` GitHub repository root-এ রাখুন।
2. **Settings → Pages → Source: GitHub Actions** নির্বাচন করুন। আগে Pages website থাকলে এই deployment সেটি replace করবে।
3. Dedicated OpenPGP private key **Actions secret `APT_SIGNING_KEY`** হিসেবে দিন। Passphrase থাকলে secret `APT_GPG_PASSPHRASE` দিন।
4. Full public key fingerprint **Actions variable `APT_KEY_FINGERPRINT`** হিসেবে দিন এবং trusted README/channel-এ public fingerprint প্রকাশ করুন। Private key কখনো commit করবেন না।
5. `main`/`master` branch-এ push করুন বা Actions workflow manually run করুন। সফল test/build/sign/deploy-এর পর APT endpoint ব্যবহার করুন।

Expected project Pages URL: `https://sh3llshad3.github.io/lab`। GitHub Pages-এর deployment output-এ অন্য URL থাকলে সেই URL ব্যবহার করুন। প্রতিটি successful workflow run নতুন package build number দেয়।

### Linux client-এ source যোগ ও প্রথম install

```bash
sudo apt update
sudo apt install -y curl gnupg
cd ~/lab-dev
```

নিচের `YOUR_VERIFIED_PUBLIC_KEY_FINGERPRINT` maintainer-এর সত্যিকারের full fingerprint দিয়ে বদলাতে হবে; এটি সরাসরি চালানোর placeholder নয়:

```bash
sudo bash packaging/add-apt-repo.sh \
  https://sh3llshad3.github.io/lab \
  YOUR_VERIFIED_PUBLIC_KEY_FINGERPRINT
```

Script downloaded public key-এর fingerprint যাচাই করে, repository-scoped key/source যোগ করে এবং `pentest-lab` install করে। Key বা Pages endpoint না থাকলে এই ধাপ কাজ করবে না।

### APT setup হয়ে গেলে নিয়মিত update

চলমান app বন্ধ করে:

```bash
sudo apt update
sudo apt upgrade
pentest-lab
```

শুধু এই app upgrade করতে:

```bash
sudo apt update
sudo apt install --only-upgrade pentest-lab
pentest-lab
```

`apt update` শুধু package indexes refresh করে; `apt upgrade`/`apt install --only-upgrade` নতুন package install করে। GitHub-এ নতুন file থাকলেও workflow publish ব্যর্থ হলে নতুন APT package পাওয়া যাবে না। APT app update করে; আলাদাভাবে installed scanners update করতে Setup ব্যবহার করুন।

### APT সমস্যা যাচাই

```bash
apt-cache policy pentest-lab
dpkg-query -W pentest-lab
cat /etc/apt/sources.list.d/pentest-lab.list
```

`Unable to locate package`, `404`, `NO_PUBKEY`, fingerprint mismatch বা workflow failure হলে Git installation হিসেবে `git pull --ff-only` ব্যবহার করতে পারেন; APT-এর signature checking disable করবেন না।

## Local Debian package দিয়ে প্রথম installation

Source ZIP-এর `release/` folder-এ built package থাকলে project folder থেকে:

```bash
sudo apt install ./release/pentest-lab_4.0.2_all.deb
pentest-lab
```

এই local installation **APT repository যোগ করে না**। ভবিষ্যতে `apt upgrade` দিয়ে lab update পেতে উপরের source setup লাগবে।

Source থেকে package build করতে:

```bash
python3 packaging/build_deb.py --output dist
```

## কোথায় files থাকে

| Component | Linux location |
|---|---|
| System scanners ও source | `/opt/pentest-lab-tools/` |
| Published scanner commands | `/usr/local/bin/` |
| Nuclei templates | `/opt/pentest-lab-tools/nuclei-templates/` |
| Git/ZIP app dependencies | Project `.venv/` |
| Git/ZIP scan history | Project `data/` |
| APT-managed application source | `/usr/share/pentest-lab/` |
| APT launcher | `/usr/bin/pentest-lab` |
| APT app runtime ও history | `~/.local/share/pentest-lab/app/` এবং তার `data/` |
| Disk temporary storage | `~/.cache/pentest-lab/tmp/` |

`XDG_DATA_HOME` set করা থাকলে APT user runtime সেই location ব্যবহার করে। Root হিসেবে চালালে paths root user-এর home অনুযায়ী হবে। একই account ব্যবহার করুন।

### Git/ZIP থেকে APT-এ history নেওয়া

সব scan/app বন্ধ করুন। আগের `data/` ও `settings.json` backup নিন। নতুন APT runtime-এ আগে history না থাকলে শুধুমাত্র ওই data/settings copy করুন। Existing runtime-এর data blindly overwrite করবেন না। পুরোনো code বা `.venv` copy করবেন না। APT installation ও Git folder আলাদা application copy।

## Windows ও WSL

Python 3.11+ ও Python Launcher install করে Git clone/ZIP-এর folder থেকে `start-windows.bat` চালান। Setup → Windows → Direct Windows বা Ubuntu WSL বেছে নিন। System-wide installation-এর জন্য Administrator terminal লাগতে পারে। WSL-এর প্রথম installation-এ restart এবং Ubuntu account setup লাগতে পারে।

Windows native tools `%ProgramData%\PentestLab\Tools`-এ, WSL tools Ubuntu-এর `/opt/pentest-lab-tools`-এ থাকে। APT পদ্ধতি Linux/Ubuntu WSL-এর জন্য; Windows native version Git/ZIP দিয়ে update করুন।

## Scan workflow ও input

Full profile-এ ১৭টি tool selectable; Core profile-এ মূল ৯টি।

1. Archive/subdomain/OSINT discovery: waybackurls, subfinder, theHarvester, DNSRecon।
2. DNS ও ports: dnsx, naabu, Nmap।
3. Live URL check: httpx। Live URL না থাকলে পরের web checks বাদ যায়।
4. Crawling: Katana, Photon; নতুন URL আবার httpx দিয়ে যাচাই।
5. আবিষ্কৃত scoped `.js/.mjs/.cjs` ফাইল: SecretFinder।
6. Parameter URL: Dalfox; path discovery: ffuf; GET parameter discovery: Arjun।
7. নতুন parameter URL-এ Dalfox, তারপর SQLmap।
8. Root URL list-এ Nuclei; তারপর Nikto এবং report export।

Domain/IP-based tools-এ hostname যায়; web tools-এ scheme, port, path ও query-সহ URL থাকে। `www` বাদ দেওয়া হয় না। SecretFinder downloaded local JavaScript পরীক্ষা করে; inline/undiscovered script সবসময় covered নয়।

Scope configured exact hostname অনুযায়ী; পাওয়া subdomain নিজে থেকে অনুমোদিত হয় না। Scope port/path restriction নয়। Default selection limits আছে; UI-তে পরিবর্তন করা যায়। Scan scheduling serial।

## Live output ও controls

- Actual command arguments এবং stdout/stderr console-এ দেখা যায়; tool buffering হলে output দেরি হতে পারে।
- Scroll উপরে নিলে auto-scroll pause হয়; **Load earlier output** ও **Jump to live** আছে।
- UI প্রায় প্রতি সেকেন্ডে refresh; Nuclei statistics প্রায় প্রতি পাঁচ সেকেন্ডে আসে।
- Nuclei Balanced: 10 req/s, 5 concurrent templates; Conservative: 3 req/s, 1 template।
- কোনো scanner-এর lab-imposed মোট execution deadline নেই; আলাদা network request timeout থাকে।
- **Stop** পুরো job বন্ধ করে। **Skip tool** চলমান invocation বন্ধ করে ওই tool-এর পরবর্তী invocation বাদ দেয়।
- **Delete scan** finished scan-এর report/log/downloaded files স্থায়ীভাবে মুছে দেয়; installed tools থাকে।

App বন্ধ/crash হলে পরের launch-এ unfinished jobs interrupted হতে পারে। Automatic scan resume নেই।

## Command diagnostics

Git/ZIP version:

```bash
cd ~/lab-dev
.venv/bin/python command_doctor.py --output command-check.json
```

APT version:

```bash
pentest-lab --doctor --output command-check.json
```

এটি installed executable ও help flags পরীক্ষা করে; target scan করে না। বিস্তারিত [COMMAND_REVIEW.md](COMMAND_REVIEW.md)। Compatibility pass মানে vulnerability পাওয়া নিশ্চিত নয়।

## Reports

Word ও HTML report-এ executive summary, candidate distribution pie chart, test execution list, tool coverage ও evidence থাকে। Word-এ finding register/IDs এবং **Developed by Nowan** footer আছে।

Chart-এর percentage unique automated candidates-এর অনুপাত; website কত শতাংশ vulnerable বা finding confirmed—তা নয়। Recon observations chart-এ বাদ থাকে। Test count হলো recorded command attempts; payload, HTTP request বা Nuclei template count নয়।

SecretFinder match values exported reports-এ লুকানো হয়। অন্য redaction best effort; raw local evidence/SQLmap traffic logs-এ sensitive content থাকতে পারে। Automated findings manual validation ছাড়া confirmed নয়; failed/skipped checks বা zero findings secure হওয়ার প্রমাণ নয়।

## Tests ও documentation

App প্রথমবার চালিয়ে dependencies install হওয়ার পর:

```bash
cd ~/lab-dev
.venv/bin/python -m unittest discover -s tests -v
```

- [TESTING.md](TESTING.md): validation ও limitations।
- [CHANGELOG.md](CHANGELOG.md): version changes।
- [packaging/APT_SETUP.md](packaging/APT_SETUP.md): signed APT publishing setup।
- [COMMAND_REVIEW.md](COMMAND_REVIEW.md): command ও target review।

Windows/WSL real installations, production GitHub Pages publishing এবং live external assessment সব build environment-এ যাচাই করা হয়নি। শুধু tool command update করলে vulnerability পাওয়ার নিশ্চয়তা হয় না।

### 4.0.2 display updates

Live output removes ANSI color/control sequences and wraps long lines inside the console. Carriage-return progress updates appear on separate lines; raw log files stay unchanged. Discovery cards show per-tool URL/host counts and up to 500 results, independently of vulnerability counts. Full parsed lists are retained in each scan folder as `discovered-TOOL.txt`. Existing scans without discovery metadata retain their original view.
