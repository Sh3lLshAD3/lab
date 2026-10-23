#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export LAB_OPEN_SETUP=1
exec bash start-linux.sh
