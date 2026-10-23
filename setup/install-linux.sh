#!/usr/bin/env bash
set -euo pipefail
LAB_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ "$(id -u)" -eq 0 ]; then SUDO=(); else SUDO=(sudo -n); fi
export DEBIAN_FRONTEND=noninteractive PYTHONUNBUFFERED=1
# apt and prerequisites must also avoid the potentially full /tmp tmpfs.
LAB_SETUP_TMP="$(mktemp -d /var/tmp/pentest-lab-setup.XXXXXXXX)"
trap 'rm -rf -- "$LAB_SETUP_TMP"' EXIT
export TMPDIR="$LAB_SETUP_TMP" TEMP="$LAB_SETUP_TMP" TMP="$LAB_SETUP_TMP" GOTMPDIR="$LAB_SETUP_TMP"
packages=(git curl wget python3 python3-venv python3-pip ca-certificates pipx libpcap-dev build-essential jq python3-tk)
selected=",${LAB_SELECTED_TOOLS:-subfinder,httpx,waybackurls,dalfox,ffuf,arjun,sqlmap,nuclei,nikto,katana,dnsrecon,nmap,dnsx,naabu,photon,theHarvester},"
if [[ "$selected" == *,nikto,* ]]; then packages+=(perl libnet-ssleay-perl libio-socket-ssl-perl); fi
if [[ "$selected" == *,nmap,* ]]; then packages+=(nmap); fi
missing=()
for pkg in "${packages[@]}"; do
 if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q 'install ok installed'; then missing+=("$pkg"); fi
done
if [ "${#missing[@]}" -gt 0 ]; then
 printf '[RUNNING] Missing system dependencies: %s\n' "${missing[*]}"
 "${SUDO[@]}" env TMPDIR="$LAB_SETUP_TMP" TEMP="$LAB_SETUP_TMP" TMP="$LAB_SETUP_TMP" apt-get update
 "${SUDO[@]}" env TMPDIR="$LAB_SETUP_TMP" TEMP="$LAB_SETUP_TMP" TMP="$LAB_SETUP_TMP" apt-get install -y "${missing[@]}"
else
 printf '[ALREADY INSTALLED] System dependencies\n'
fi
# All selected tools are published under /usr/local/bin with sources in /opt.
# Keep privilege in the installer only; the dashboard should run as a normal user.
if [ "$(id -u)" -ne 0 ]; then
 sudo -n env LAB_SELECTED_TOOLS="${LAB_SELECTED_TOOLS:-subfinder,httpx,waybackurls,dalfox,ffuf,arjun,sqlmap,nuclei,nikto,katana,dnsrecon,nmap,dnsx,naabu,photon,theHarvester}" LAB_UPDATE_TOOLS="${LAB_UPDATE_TOOLS:-0}" python3 -u "$LAB_ROOT/setup/install_tools.py"
else
 python3 -u "$LAB_ROOT/setup/install_tools.py"
fi
