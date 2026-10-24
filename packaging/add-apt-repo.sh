#!/usr/bin/env bash
set -euo pipefail
if [[ $(id -u) != 0 ]]; then echo 'Run with sudo.' >&2; exit 1; fi
repo_url="${1:?Usage: sudo bash packaging/add-apt-repo.sh HTTPS_APT_URL EXPECTED_KEY_FINGERPRINT}"
expected="${2:?Expected signing-key fingerprint is required}"
[[ "$repo_url" =~ ^https://[A-Za-z0-9.-]+(/[A-Za-z0-9._~/-]*)?$ ]] || { echo 'Invalid HTTPS repository URL' >&2; exit 1; }
expected="${expected^^}"
[[ "$expected" =~ ^[0-9A-F]{40}$|^[0-9A-F]{64}$ ]] || { echo 'Invalid fingerprint' >&2; exit 1; }
repo_url="${repo_url%/}"
for tool in curl gpg; do command -v "$tool" >/dev/null || { echo "Install prerequisite: $tool" >&2; exit 1; }; done
repo_tmp=$(mktemp -d /var/tmp/pentest-lab-apt.XXXXXXXX)
trap 'rm -rf -- "$repo_tmp"' EXIT
curl --fail --silent --show-error --proto '=https' --tlsv1.2 "$repo_url/public-key.asc" -o "$repo_tmp/key.asc"
actual=$(gpg --batch --show-keys --with-colons "$repo_tmp/key.asc" | awk -F: '$1=="fpr" {print $10;exit}')
[[ "$actual" == "$expected" ]] || { echo 'Signing key fingerprint mismatch. Nothing installed.' >&2; exit 1; }
install -d -m 755 /usr/share/keyrings
install -m 644 "$repo_tmp/key.asc" /usr/share/keyrings/pentest-lab.asc
printf 'deb [signed-by=/usr/share/keyrings/pentest-lab.asc] %s ./\n' "$repo_url" > /etc/apt/sources.list.d/pentest-lab.list
apt-get update
apt-get install pentest-lab
