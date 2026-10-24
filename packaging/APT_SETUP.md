# GitHub to signed APT updates

These files implement publishing; they do not configure your GitHub account automatically. Source repository: https://github.com/Sh3lLshAD3/lab (verified by a read-only clone at commit 2e3759c). No remote repo, signing key or Pages deployment was changed here.

## Maintainer setup once

1. Put the contents of the project at your GitHub repository root. In particular `.github/workflows/apt.yml` must be at repository root. If keeping the `Pentest_Lab_Unified` subdirectory, move its `.github` folder to repository root; the workflow supports either source location.
2. In GitHub Settings > Pages choose **GitHub Actions** as the source. Publishing replaces the Pages website with this APT repository; use a separate repository if that site already hosts something important. Pages and Actions must be available for your account/repository.
3. Create or use a dedicated OpenPGP signing key. Keep the private key outside the source repository. For example, on your own machine:

   ```bash
   gpg --full-generate-key
   gpg --list-secret-keys --keyid-format long
   gpg --armor --export-secret-keys YOUR_FINGERPRINT > apt-private-key.asc
   ```

4. Add the contents of that private key file as Actions secret **APT_SIGNING_KEY**. If passphrase protected, set secret **APT_GPG_PASSPHRASE**. Set Actions variable **APT_KEY_FINGERPRINT** to the full primary-key fingerprint (no spaces). Never commit the private key. Publish the public fingerprint in README through a trusted channel.
5. Push to `main` or `master`, or run the workflow manually. It tests the project, creates `pentest-lab_VERSION+gitRUN_NUMBER_all.deb`, generates package indexes and signs Release/InRelease, then deploys Pages. Check Actions success before using the repository.
6. The deployment page URL is the APT base URL, usually `https://sh3llshad3.github.io/lab`. Custom domain/user-site repositories may use a different URL; use the actual Pages deployment URL.

Each push gets a higher build number for the same app version; increment `version.py` for a new app release. Do not decrease versions or recreate the repo with a lower counter without bumping the app version. The repository retains the current build, not a rollback archive. APT chooses the higher version; merely changing a source file on GitHub without a successful publish does not update Linux clients.

## Linux setup once

Install curl and gnupg if missing, then use the actual URL and independently verified public key fingerprint:

```bash
sudo bash packaging/add-apt-repo.sh https://sh3llshad3.github.io/lab YOUR_FINGERPRINT
```

The script verifies the key fingerprint, installs a repository-scoped Signed-By key, adds the source, then installs `pentest-lab`.

## Normal updates

```bash
sudo apt update
sudo apt upgrade
pentest-lab
```

Or update just this app with `sudo apt install --only-upgrade pentest-lab`. `apt update` refreshes indexes; `apt upgrade` installs available newer packages. Close the running app before relaunching the upgraded version. Upgrading the Debian package updates app code; it does not automatically upgrade independently installed scanners or templates. Use Setup > selected tools > Update for those.

APT code lives under `/usr/share/pentest-lab`; launching synchronizes it to `~/.local/share/pentest-lab/app`. Launching as root uses root’s home; use the same account to retain history. Scans, settings and the app venv stay in that per-user runtime. Existing ZIP installations are separate: finish/stop scans and copy only `data/` and `settings.json` into the per-user runtime before first launch if you want old history. Do not copy old app code over APT-managed runtime code. Scanner sources stay under `/opt/pentest-lab-tools`.

## Local build and repository validation

```bash
python3 packaging/build_deb.py --output dist
# With a signing key imported into a private GNUPGHOME:
python3 packaging/publish_apt.py --packages dist --output apt-site --key YOUR_FINGERPRINT
```

Building requires dpkg-deb. Publishing requires apt-ftparchive (apt-utils) and gpg. No signing private key is shipped in this project. App dependencies are installed into a per-user venv on first launch; network access may be required. Package uninstall does not delete per-user scan data.

## Validation status
The Debian payload and a signed flat repository were tested locally using isolated APT lists. The production workflow has not been deployed. Local GPG agent sockets are unavailable, so local signature validation used an ephemeral sq-generated key and gpgv; the workflow uses standard GPG on GitHub runners. No test key is shipped.
