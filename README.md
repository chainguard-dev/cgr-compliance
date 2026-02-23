# cgr-compliance

Auto Generate CVE related POA&Ms and FedRAMP KSIs

* Scan a Chainguard Image with grype or trivy
* Check NVD for CVE and CISA KEV related Information
* Use chainctl to check for advisories
* Generate a Plan of Action & Milestones (POA&M) in FedRAMP, CMMC, and FedRAMP KSI (20x) format
 
## Notes

To avoid getting throttled by NVD, this script generates all scan results generating a unique list of CVEs to query NVD, then parses the saved scan results. This is to ensure that if 10 images have the same CVE ID that NVD only gets queried one time.

### POA&Ms require system context 

You are responsible for your own POA&M. POA&Ms generated using this project are not authoritative, require user review, and some fields may not be able to be filled in without system context. Any filled that cannot be filled without system context will be left blank

The logic for filling in the controls column is as follows:
- Adds the NIST 800-53 control RA-5 (Vulnerability Monitoring and Scanning) for all CVE findings
- Adds the NIST 800-53 control SI-2 (Flaw Remediation) when there is a fix available
— (TODO) Adds NIST 800-53 controls using the [CWE-to-NIST mapping maintained by Mitre](https://raw.githubusercontent.com/mitre/heimdall_tools/refs/heads/master/lib/data/cwe-nist-mapping.csv)

### POA&M Templates

* Templates used to generate these artifacts are on the /formats folder
* CSV templates were manually generated from the official Templates and Schemas
* Template References:
  * [FedRAMP Rev5 POA&M Template](https://www.fedramp.gov/resources/templates/FedRAMP-POAM-Template.xlsx)
  * [CMMC NIST 800-171 rev3](https://csrc.nist.gov/files/pubs/sp/800/171/r2/upd1/final/docs/cui-plan-of-action-template-final.docx)
  * [FedRAMP KSIs](https://raw.githubusercontent.com/FedRAMP/docs/refs/heads/main/tools/templates/FedRAMP.schema.json)
* Misc
  * You may notice the CMMC template is rev2 which aligns with [rev3 guidance to use the rev2 template](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.1318.pdf)
  * CSPs serving DoD under DFARS 7012 may use the FedRAMP POA&M template
    * https://dodcio.defense.gov/Portals/0/Documents/Library/FEDRAMP-EquivalencyCloudServiceProviders.pdf
    * https://dodcio.defense.gov/Portals/0/Documents/CMMC/FedRAMP-AuthorizationEquivalency.pdf
  * [DoD system owners should track CVE findings using eMASS](https://www.dcsa.mil/Portals/91/Documents/CTP/tools/NISP%20eMASS%20Industry%20Operation%20Guide%20Version%201.pdf)
    * For users with a common access card (CAC) A POA&M Template is available in the “Help” section of eMASS

## Requirements

### Tools

The following tools must be installed and available in your system `PATH`:

- [chainctl](https://edu.chainguard.dev/chainguard/chainctl-usage/how-to-install-chainctl/)
- [grype](https://github.com/anchore/grype)
- [trivy](https://github.com/aquasecurity/trivy)
- [crane](https://github.com/google/go-containerregistry/tree/main/cmd/crane)
- [cosign](https://github.com/sigstore/cosign)


You can verify they are installed by running:

```bash
crane version
trivy --version
cosign version
grype version
chainctl version
```

### NVD API Key

This program requires an NVD API Key. You can [request an NVD API key for free from NIST](https://nvd.nist.gov/developers/request-an-api-key)

## Usage

  ### Clone the Repository

  ```bash
  git clone https://github.com/chainguard-dev/cgr-compliance.git
  cd cgr-compliance
  ```

  ### Export Your NVD API Key

  ```bash
  export NVD_API_KEY="your-nvd-api-key-here"
  ```

## Other frameworks

If you need to map these scan results to other security/compliance frameworks checkout MITRE’s Center for Threat-Informed Defense (CTID) which uses the Cloud Security Alliance Cloud Controls Matrix to map to many other frameworks: See:
- https://ctid.mitre.org/blog/2026/01/28/cloud-security-built-with-attck/ 
- https://github.com/center-for-threat-informed-defense/mappings-explorer
- https://ctid.mitre.org/projects/nist-800-53-control-mappings/ 



