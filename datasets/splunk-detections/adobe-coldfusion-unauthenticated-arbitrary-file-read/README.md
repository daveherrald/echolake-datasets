# Adobe ColdFusion Unauthenticated Arbitrary File Read

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting potential exploitation of the Adobe ColdFusion vulnerability, CVE-2023-26360, which allows unauthenticated arbitrary file read. It monitors web requests to the "/cf_scripts/scripts/ajax/ckeditor/*" path using the Web datamodel, focusing on specific ColdFusion paths to differentiate malicious activity from normal traffic. This activity is significant due to the vulnerability's high CVSS score of 9.8, indicating severe risk. If confirmed malicious, it could lead to unauthorized data access, further attacks, or severe operational disruptions, necessitating immediate investigation.

## MITRE ATT&CK

- T1190

## Analytic Stories

- Adobe ColdFusion Arbitrary Code Execution CVE-2023-29298 CVE-2023-26360

## Data Sources

- Suricata

## Sample Data

- **Source:** suricata
  **Sourcetype:** suricata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/adobe/cve_2023_29360_coldfusion.log


---

*Source: [Splunk Security Content](detections/web/adobe_coldfusion_unauthenticated_arbitrary_file_read.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
