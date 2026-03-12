#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CGRREPO="${CGRREPO:-cgr-demo.com}"
CERT_IDENTITY_REGEXP="${CERT_IDENTITY_REGEXP:-https://issuer.enforce.dev/(4cf15780a13a9b6576d8b357e6524554c8c12a18/c03040118377d88c|4cf15780a13a9b6576d8b357e6524554c8c12a18/ca93125e202f81f8)}"

chainctl images repos list --parent="$CGRREPO" -o json \
  | jq -r '.items[].name | select(contains("fips"))' \
  | sort -u \
  | while read -r IMAGE; do
      
      imagenamefull="cgr.dev/${CGRREPO}/${IMAGE}:latest"
      file="$(mktemp "/tmp/${IMAGE}.XXXXXX-cyclonedx.json")"

      crane manifest "$imagenamefull" \
        | jq -r '.manifests[] | select(.platform.architecture == "amd64") | .digest' \
        | xargs -I {} cosign verify-attestation \
            --type="https://cyclonedx.org/bom" \
            --certificate-oidc-issuer="https://issuer.enforce.dev" \
            --certificate-identity-regexp="$CERT_IDENTITY_REGEXP" \
            "$imagenamefull@{}" 2>/dev/null \
        | jq -r '.payload' \
        | base64 -d \
        | jq '.predicate' \
        > "$file"

      "$SCRIPT_DIR/cmvp-csv.sh" "$IMAGE" "$file"

      rm -f "$file"
    done