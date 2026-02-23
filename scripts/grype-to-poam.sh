#!/bin/bash

set -euo pipefail

export GRYPE_DEFAULT_IMAGE_PULL_SOURCE=registry
INPUT_FILE="inputs/images.txt"
nvd_base_url="https://services.nvd.nist.gov/rest/json/cves/2.0"
cve_out_dir="output/vuln-data"
nvd_out_dir="${cve_out_dir}/nvd/"
grype_out_dir="${cve_out_dir}/grype/"
poam_out_dir="output/poams"
cves=()
images=()
mkdir -p "$cve_out_dir" "$nvd_out_dir" "$grype_out_dir" "$poam_out_dir"

if [[ -z "${NVD_API_KEY:-}" ]]; then
  echo "Error: NVD_API_KEY environment variable is not set"
  exit 1
fi

if [[ ! -f "$INPUT_FILE" ]]; then
  echo "Error: $INPUT_FILE not found"
  exit 1
fi

# Remove all files in the directories safely
echo "Clearing the following directories: $grype_out_dir, $nvd_out_dir, $poam_out_dir"
find "$grype_out_dir" -type f -exec rm -f {} +
find "$nvd_out_dir" -type f -exec rm -f {} +
find "$poam_out_dir" -type f -exec rm -f {} +

# Generate the POA&M file with just the headers
today=$(date +%F)
poam_file="$poam_out_dir/FedRAMP-POAM-Template-$today.csv"
cp "formats/FedRAMP-POAM-Template.csv" "$poam_out_dir/FedRAMP-POAM.csv"

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
    
    origimagestr="${images[i]}"
    
    # Pull the image and check for errors
    if docker pull "${images[i]}" 2>&1 | grep -iq "error"; then
      echo "Error encountered while pulling ${images[i]}. Exiting..."
      exit 1
    fi
    
    created=$(crane config "${images[i]}" | jq -r '.created | split("T")[0]')

done

# ---- Helper: sanitize a string for filenames ----
sanitize() {
  echo "$1" | tr '/:@' '___' | tr -cd 'A-Za-z0-9._-'
}

for image in "${images[@]}"; do
    
    # Ensure tag
    [[ "$image" != *:* ]] && image="${image}:latest"

    echo "Scanning image: $image"

    # Pull the image and check for errors
    if docker pull "${images[i]}" 2>&1 | grep -iq "error"; then
        echo "Error encountered while pulling ${images[i]}. Exiting..."
        exit 1
    fi

    created=$(crane config "${images[i]}" | jq -r '.created | split("T")[0]')

    # Save grype JSON
    img_tag_sane="$(sanitize "$image")"
    grype_json_path="${grype_out_dir}/grype_${img_tag_sane}.json"

    grype_json="$(grype "$image" --output=json 2>/dev/null | jq)"
    echo "${grype_json}" > "${grype_json_path}"

    # Extract unique CVE IDs (critical and high only)
    # mapfile -t cves < <(echo "${grype_json}" | jq -r '
    # .matches[]?
    # | select((.vulnerability.severity | ascii_upcase) == "HIGH" or (.vulnerability.severity | ascii_upcase) == "CRITICAL")
    # | .vulnerability.id
    # | select(startswith("CVE-"))
    # ' | sort -u)

    # Extract unique CVE IDs 
    mapfile -t cves < <(echo "${grype_json}" | jq -r '
    .matches[]?
    | .vulnerability.id
    | select(startswith("CVE-"))
    ' | sort -u)

done

if [[ ${#cves[@]} -eq 0 ]]; then
    echo "-> No CVEs found in grype results. POA&M is empty"
    exit
fi
nvd_tmp_file="$(mktemp --suffix=.json)"
trap 'rm -f "$nvd_tmp_file"' EXIT

for cve in "${cves[@]}"; do

    if [[ "$cve" == CVE-* ]]; then
        
        api_url="$nvd_base_url?cveId=$cve"
        #http_code=$(curl -sS -H "Accept: application/json" -H "apiKey: $NVD_API_KEY" -o "$nvd_out_dir/nvd-cve-data-including-cisa-kev.json" -w "%{http_code}" "$api_url")
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
        jq . "$nvd_tmp_file" > "$nvd_out_dir/nvd-cve-data-including-cisa-kev.json"
    
        cisaExploitAdd=$(jq -r '.vulnerabilities[].cve.cisaExploitAdd // empty' "$nvd_out_dir/nvd-cve-data-including-cisa-kev.json")
        cisaActionDue=$(jq -r '.vulnerabilities[].cve.cisaActionDue // empty' "$nvd_out_dir/nvd-cve-data-including-cisa-kev.json")
        cisaRequiredAction=$(jq -r '.vulnerabilities[].cve.cisaRequiredAction // empty' "$nvd_out_dir/nvd-cve-data-including-cisa-kev.json")
        cisaVulnerabilityName=$(jq -r '.vulnerabilities[].cve.cisaVulnerabilityName // empty' "$nvd_out_dir/nvd-cve-data-including-cisa-kev.json")

        # If any CISA KEV fields exist, print details
        if [[ -n "$cisaExploitAdd" || -n "$cisaActionDue" || -n "$cisaRequiredAction" || -n "$cisaVulnerabilityName" ]]; then

            baseScore=$(jq -r '
                .vulnerabilities[].cve.metrics.cvssMetricV31[0]?.cvssData.baseScore
                // .vulnerabilities[].cve.metrics.cvssMetricV30[0]?.cvssData.baseScore
                // .vulnerabilities[].cve.metrics.cvssMetricV2[0]?.cvssData.baseScore
                // "N/A"
            ' "$nvd_out_dir/nvd-cve-data-including-cisa-kev.json")

            baseSeverity=$(jq -r '
                .vulnerabilities[].cve.metrics.cvssMetricV31[0]?.cvssData.baseSeverity
                // .vulnerabilities[].cve.metrics.cvssMetricV30[0]?.cvssData.baseSeverity
                // .vulnerabilities[].cve.metrics.cvssMetricV2[0]?.baseSeverity
                // "N/A"
            ' "$nvd_out_dir/nvd-cve-data-including-cisa-kev.json")
        
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

    write_cve "$cve"
done

echo "Done. Outputs saved under: ${out_dir}/"

write_cve() {
  local cve="$1"
  echo "$cve" >> "$poam_file"
}

# Call the function
