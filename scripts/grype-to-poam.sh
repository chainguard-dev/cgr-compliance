#!/usr/bin/env bash

set -euo pipefail

export GRYPE_DEFAULT_IMAGE_PULL_SOURCE=registry
INPUT_FILE="inputs/images.txt"
nvd_base_url="https://services.nvd.nist.gov/rest/json/cves/2.0"
cve_out_dir="output/vuln-data"
nvd_out_dir="${cve_out_dir}/nvd/"
grype_out_dir="${cve_out_dir}/grype/"
poam_out_dir="output/poam"
cves=()
images=()
poam_id=1
declare -A cve_asset_ids      # cve -> comma-separated asset identifiers across all images
declare -A cve_first_grype    # cve -> grype JSON path for the first image that found it
declare -A image_created_dates # image -> .created date from OCI config (cached per image)
use_outputs_dir=false
for arg in "$@"; do
  [[ "$arg" == "--use-outputs-dir" ]] && use_outputs_dir=true
done
mkdir -p "$cve_out_dir" "$nvd_out_dir" "$grype_out_dir" "$poam_out_dir"

if [[ "$use_outputs_dir" == false ]]; then
  if [[ -z "${NVD_API_KEY:-}" ]]; then
    echo "Error: NVD_API_KEY environment variable is not set"
    exit 1
  fi
fi

if [[ ! -f "$INPUT_FILE" ]]; then
  echo "Error: $INPUT_FILE not found"
  exit 1
fi

# Remove all files in the directories safely
if [[ "$use_outputs_dir" == true ]]; then
  echo "Clearing the following directories: $poam_out_dir"
  find "$poam_out_dir" -type f -exec rm -f {} +
else
  echo "Clearing the following directories: $nvd_out_dir, $poam_out_dir"
  find "$nvd_out_dir" -type f -exec rm -f {} +
  find "$poam_out_dir" -type f -exec rm -f {} +
fi

# Generate the POA&M file with just the headers
today=$(date +%F)
poam_file="$poam_out_dir/chainguard-fedramp-poam.csv"
cp "formats/FedRAMP-POAM-Template.csv" "$poam_file"

while IFS= read -r line || [[ -n "$line" ]]; do
  # Trim leading/trailing whitespace
  line="$(echo "$line" | xargs)"
  # Skip blank lines and comments
  [[ -z "$line" || "$line" == \#* ]] && continue
  images+=("$line")
done < "$INPUT_FILE"

# Loop through each item and append ":latest" if no tag is present
for i in "${!images[@]}"; do
    if [[ "${images[i]}" != *:* ]]; then
        images[i]="${images[i]}:latest"
    fi
done

# ---- Helper: sanitize a string for filenames ----
sanitize() {
  echo "$1" | tr '/:@' '___' | tr -cd 'A-Za-z0-9._-'
}

# ---- Helper: escape a value for CSV ----
csv_escape() {
  local value="${1:-}"
  echo "\"${value//\"/\"\"}\""
}

# ---- Helper: write one FedRAMP POA&M row to the output CSV ----
write_fedramp_poam() {
  local cve="$1"
  local asset_id="$2"
  local grype_json_path="$3"

  # Pull all match fields for this CVE from the grype JSON
  local match_json
  match_json=$(jq -c --arg cve "$cve" 'first(.matches[]? | select(.vulnerability.id == $cve))' "$grype_json_path")

  local fix_state fix_version
  fix_state=$(echo "$match_json"   | jq -r '.vulnerability.fix.state // "unknown"')
  fix_version=$(echo "$match_json" | jq -r '.vulnerability.fix.versions[0] // ""')

  # Adds the NIST 800-53 control RA-5 (Vulnerability Monitoring and Scanning) for all CVE findings
  # Adds the NIST 800-53 control SI-2 (Flaw Remediation) when there is a fix available
  local controls="RA-5"
  [[ "$fix_state" == "fixed" ]] && controls="RA-5, SI-2"

  # Weakness Name, Description, Detector Source, Source Identifier — from CWE-NIST mapping
  # Prefer Primary (nvd@nist.gov) CWE; fall back to first available
  local cwe_id weakness_name weakness_description weakness_detector_source weakness_source_id
  cwe_id=$(echo "$match_json" | jq -r 'first(
    ((.vulnerability.cwes // [])[] | select(.type == "Primary") | .cwe),
    ((.vulnerability.cwes // [])[0]?.cwe),
    ""
  )')

  weakness_name=""
  weakness_description=""
  weakness_detector_source=""
  weakness_source_id="$cwe_id"

  if [[ -n "$cwe_id" ]]; then
    local cwe_num cwe_row
    cwe_num="${cwe_id#CWE-}"
    cwe_row=$(awk -F',' -v id="$cwe_num" 'NR>1 { gsub(/^[[:space:]]+|[[:space:]]+$/, "", $1); if ($1 == id) { print; exit } }' "formats/cwe-nist-mapping.csv")
    if [[ -n "$cwe_row" ]]; then
      weakness_name=$(echo "$cwe_row"             | awk -F',' '{gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2}')
      weakness_detector_source=$(echo "$cwe_row"  | awk -F',' '{gsub(/^[[:space:]]+|[[:space:]]+$/, "", $3); print $3}')
      weakness_description=$(echo "$cwe_row"      | awk -F',' '{gsub(/^[[:space:]]+|[[:space:]]+$/, "", $5); print $5}')
    fi
  fi

  # Remediation Plan and Scheduled Completion Date depend on fix availability
  local remediation scheduled_completion
  if [[ "$fix_state" == "fixed" ]]; then
    remediation="Fix available, update required: update to ${fix_version}"
    scheduled_completion=""
  else
    remediation="pending upstream fix"
    scheduled_completion="pending upstream fix"
  fi

  # Original Detection Date: NVD published date
  local original_detection_date=""
  local nvd_file="$nvd_out_dir/nvd-${cve}.json"
  if [[ -f "$nvd_file" ]]; then
    original_detection_date=$(jq -r '.vulnerabilities[].cve.published // ""' "$nvd_file" | cut -dT -f1)
  fi

  # Original Risk Rating: NVD CVSS base score
  local original_risk_rating=""
  if [[ -f "$nvd_file" ]]; then
    original_risk_rating=$(jq -r '
      .vulnerabilities[].cve.metrics.cvssMetricV31[0]?.cvssData.baseScore //
      .vulnerabilities[].cve.metrics.cvssMetricV30[0]?.cvssData.baseScore //
      .vulnerabilities[].cve.metrics.cvssMetricV2[0]?.cvssData.baseScore //
      ""
    ' "$nvd_file")
  fi
  # Fall back to grype's NVD-sourced CVSS if NVD file is not available
  if [[ -z "$original_risk_rating" ]]; then
    original_risk_rating=$(echo "$match_json" | jq -r 'first(
      ((.vulnerability.cvss // [])[] | select(.source == "nvd@nist.gov") | .metrics.baseScore),
      ""
    )')
  fi

  # Adjusted Risk Rating: NVD CVSS base score (same source as Original Risk Rating per mapping)
  local adjusted_risk_rating="$original_risk_rating"

  # Last Vendor Check-in Date: .created timestamp from OCI image config (cached from image scan loop)
  local first_image last_vendor_checkin
  first_image=$(jq -r '.source.target.userInput // ""' "$grype_json_path")
  last_vendor_checkin="${image_created_dates[$first_image]:-$today}"

  # Supporting Documents: chainctl changelog (latest 5 updates); empty if chainctl unavailable/unauthenticated
  local supporting_docs=""
  if command -v chainctl &>/dev/null; then
    supporting_docs=$(chainctl images changelog "$first_image" --depth 5 2>/dev/null | tr '\n' ' ' || true)
  fi

  # POAM ID,Controls,Weakness Name,Weakness Description,Weakness Detector Source,
  # Weakness Source Identifier,Asset Identifier,Point of Contact,Resources Required,
  # Remediation Plan,Original Detection Date,Scheduled Completion Date,Status Date,
  # Vendor Dependency,Last Vendor Check-in Date,Vendor Dependent Product Name,
  # Original Risk Rating,Adjusted Risk Rating,Risk Adjustment,False Positive,
  # Operational Requirement,Deviation Rationale,Supporting Documents,Comments,
  # Binding Operational Directive 22-01 tracking,Binding Operational Directive 22-01 Due Date,CVE
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$(csv_escape "V-$poam_id")" \
    "$(csv_escape "$controls")" \
    "$(csv_escape "$weakness_name")" \
    "$(csv_escape "$weakness_description")" \
    "$(csv_escape "$weakness_detector_source")" \
    "$(csv_escape "$weakness_source_id")" \
    "$(csv_escape "$asset_id")" \
    "$(csv_escape "$poc")" \
    "$(csv_escape "")" \
    "$(csv_escape "$remediation")" \
    "$(csv_escape "$original_detection_date")" \
    "$(csv_escape "$scheduled_completion")" \
    "$(csv_escape "$today")" \
    "$(csv_escape "Chainguard")" \
    "$(csv_escape "$last_vendor_checkin")" \
    "$(csv_escape "Chainguard Images")" \
    "$(csv_escape "$original_risk_rating")" \
    "$(csv_escape "$adjusted_risk_rating")" \
    "$(csv_escape "N/A")" \
    "$(csv_escape "Grype")" \
    "$(csv_escape "")" \
    "$(csv_escape "")" \
    "$(csv_escape "$supporting_docs")" \
    "$(csv_escape "")" \
    "$(csv_escape "")" \
    "$(csv_escape "")" \
    "$(csv_escape "$cve")" \
    >> "$poam_file"

  ((poam_id++))
}

for image in "${images[@]}"; do

    img_tag_sane="$(sanitize "$image")"
    grype_json_path="${grype_out_dir}/grype_${img_tag_sane}.json"

    # Use existing grype scan results if available, otherwise run a fresh scan
    if [[ -f "$grype_json_path" ]]; then
        echo "Using cached grype results for $image"
    else
        echo "Scanning image: $image"
        grype "$image" --output=json 2>/dev/null | jq . > "$grype_json_path"
    fi

    # Cache the OCI image .created date (used for Last Vendor Check-in Date)
    image_created_dates["$image"]=$(crane config "$image" 2>/dev/null | jq -r '.created | split("T")[0]' 2>/dev/null || echo "$today")

    # Extract unique CVE IDs and track which image and grype file they came from
    # mapfile -t image_cves < <(echo "${grype_json}" | jq -r '
    # .matches[]?
    # | select((.vulnerability.severity | ascii_upcase) == "HIGH" or (.vulnerability.severity | ascii_upcase) == "CRITICAL")
    # | .vulnerability.id
    # | select(startswith("CVE-"))
    # ' | sort -u)

    # Extract unique CVE IDs
    mapfile -t image_cves < <(jq -r '
    .matches[]?
    | .vulnerability.id
    | select(startswith("CVE-"))
    ' "$grype_json_path" | sort -u)

    for cve in "${image_cves[@]}"; do
        cves+=("$cve")

        # Build asset identifier: image:tag (@sha256:manifestDigest)
        manifest_digest=$(jq -r '.source.target.manifestDigest // ""' "$grype_json_path")
        asset_id="$image"
        [[ -n "$manifest_digest" ]] && asset_id="${image} (@${manifest_digest})"

        # Aggregate asset identifiers and track first grype path per unique CVE
        if [[ -v cve_asset_ids["$cve"] ]]; then
            cve_asset_ids["$cve"]+=" , ${asset_id}"
        else
            cve_asset_ids["$cve"]="$asset_id"
            cve_first_grype["$cve"]="$grype_json_path"
        fi
    done

done

# Deduplicate cves array (preserving first-seen order) so NVD is queried once per CVE
declare -A _seen_cves=()
declare -a _unique_cves=()
for cve in "${cves[@]}"; do
    if [[ ! -v _seen_cves["$cve"] ]]; then
        _unique_cves+=("$cve")
        _seen_cves["$cve"]=1
    fi
done
cves=("${_unique_cves[@]}")

if [[ ${#cves[@]} -eq 0 ]]; then
    echo "-> No CVEs found in grype results. POA&M is empty"
    exit
fi
nvd_tmp_file="$(mktemp -t nvd-tmp.XXXXXX).json"
trap 'rm -f "$nvd_tmp_file"' EXIT

# Point of Contact: current git user (constant for this run)
poc=$(git config user.name 2>/dev/null || git config user.email 2>/dev/null || echo "")

for cve in "${cves[@]}"; do

    if [[ "$cve" == CVE-* && "$use_outputs_dir" == false ]]; then

        api_url="$nvd_base_url?cveId=$cve"
        http_code=$(curl -sS -H "Accept: application/json" -H "apiKey: $NVD_API_KEY" -o "$nvd_tmp_file" -w "%{http_code}" "$api_url")

        # Retry while HTTP code is 429
        while [[ "$http_code" -eq 429 ]]; do
            # echo "Rate limited (429) for $cve. Waiting 10 seconds before retrying..."
            sleep 10
            http_code=$(curl -sS -H "Accept: application/json" \
                                -H "apiKey: $NVD_API_KEY" \
                                -o "$nvd_tmp_file" \
                                -w "%{http_code}" "$api_url")
        done

        if [[ "$http_code" -ne 200 ]]; then
            echo "NVD request failed (HTTP $http_code) for $api_url"
            cat "$nvd_tmp_file"
            exit 1
        fi

        # Make pretty
        jq . "$nvd_tmp_file" > "$nvd_out_dir/nvd-${cve}.json"

        cisaExploitAdd=$(jq -r '.vulnerabilities[].cve.cisaExploitAdd // empty'             "$nvd_out_dir/nvd-${cve}.json")
        cisaActionDue=$(jq -r '.vulnerabilities[].cve.cisaActionDue // empty'               "$nvd_out_dir/nvd-${cve}.json")
        cisaRequiredAction=$(jq -r '.vulnerabilities[].cve.cisaRequiredAction // empty'     "$nvd_out_dir/nvd-${cve}.json")
        cisaVulnerabilityName=$(jq -r '.vulnerabilities[].cve.cisaVulnerabilityName // empty' "$nvd_out_dir/nvd-${cve}.json")

        # If any CISA KEV fields exist, print details
        if [[ -n "$cisaExploitAdd" || -n "$cisaActionDue" || -n "$cisaRequiredAction" || -n "$cisaVulnerabilityName" ]]; then

            baseScore=$(jq -r '
                .vulnerabilities[].cve.metrics.cvssMetricV31[0]?.cvssData.baseScore
                // .vulnerabilities[].cve.metrics.cvssMetricV30[0]?.cvssData.baseScore
                // .vulnerabilities[].cve.metrics.cvssMetricV2[0]?.cvssData.baseScore
                // "N/A"
            ' "$nvd_out_dir/nvd-${cve}.json")

            baseSeverity=$(jq -r '
                .vulnerabilities[].cve.metrics.cvssMetricV31[0]?.cvssData.baseSeverity
                // .vulnerabilities[].cve.metrics.cvssMetricV30[0]?.cvssData.baseSeverity
                // .vulnerabilities[].cve.metrics.cvssMetricV2[0]?.baseSeverity
                // "N/A"
            ' "$nvd_out_dir/nvd-${cve}.json")

            echo ""
            echo "**************"
            echo "CVE Found with CISA KEV"
            echo "CVE ID: $cve"
            echo "Base Score: $baseScore"
            echo "Base Severity: $baseSeverity"
            echo "CISA Exploit Add: $cisaExploitAdd"
            echo "CISA Action Due: $cisaActionDue"
            echo "CISA Required Action: $cisaRequiredAction"
            echo "CISA Vulnerability Name: $cisaVulnerabilityName"
            echo "**************"
            echo ""

        fi
    fi

    write_fedramp_poam "$cve" "${cve_asset_ids[$cve]}" "${cve_first_grype[$cve]}"
done

echo "Done. Outputs saved under: ${poam_out_dir}/"


