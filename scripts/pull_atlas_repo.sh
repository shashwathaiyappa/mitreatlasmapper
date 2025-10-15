#!/usr/bin/env bash
set -euo pipefail
mkdir -p vendor
if [ ! -d vendor/atlas-navigator-data ]; then
  git clone --depth 1 https://github.com/mitre-atlas/atlas-navigator-data.git vendor/atlas-navigator-data
else
  git -C vendor/atlas-navigator-data pull --ff-only
fi
echo "ATLAS STIX file is at vendor/atlas-navigator-data/dist/stix-atlas.json"