#!/usr/bin/env bash
# Print CSV of NIST CMVP entries from cyclonedx.json:
#   cert_url, supplier_name, module_name
#
# Usage: ./cmvp-csv.sh [cyclonedx.json]

set -euo pipefail

IMAGE_SHORT_NAME="${1:?image_short_name required}"
BOM="${2:-cyclonedx.json}"

# Extract CMVP entries: tab-separated download_url and supplier.name
jq -r '
  def walk:
    if type == "array" then .[]
    elif type == "object" then
      (if .purl? | strings | startswith("pkg:generic/NIST-CMVP") then . else empty end),
      (.components[]? | walk)
    else empty
    end;
  .components[] | walk |
  [ (.purl | split("?download_url=")[1] | @uri | ltrimstr("") ),
    (.purl | split("?download_url=")[1]),
    .supplier.name ]
  | @tsv
' "$BOM" | while IFS=$'\t' read -r _encoded url supplier; do
  # URL-decode the download_url
  cert_url=$(python3 -c "from urllib.parse import unquote; import sys; print(unquote(sys.argv[1]))" "$url")
  cert_num="${cert_url##*/}"

  # Fetch module name from NIST certificate page
  module_name=$(curl -s "https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/${cert_num}" \
    | grep -A1 'id="module-name"' \
    | tail -1 \
    | sed 's/^[[:space:]]*//' \
    | sed 's/[[:space:]]*$//')

  printf '%s,%s,%s,%s\n' \
    "$IMAGE_SHORT_NAME" "$cert_url" "$supplier" "$module_name"
done
