# Adobe ColdFusion Access Control Bypass

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects potential exploitation attempts against Adobe ColdFusion vulnerabilities CVE-2023-29298 and CVE-2023-26360. It monitors requests to specific ColdFusion Administrator endpoints, especially those with an unexpected additional forward slash, using the Web datamodel. This activity is significant for a SOC as it indicates attempts to bypass access controls, which can lead to unauthorized access to ColdFusion administration endpoints. If confirmed malicious, this could result in data theft, brute force attacks, or further exploitation of other vulnerabilities, posing a serious security risk to the environment.

## MITRE ATT&CK

- T1190

## Analytic Stories

- Adobe ColdFusion Arbitrary Code Execution CVE-2023-29298 CVE-2023-26360

## Data Sources

- Suricata

## Sample Data

- **Source:** suricata
  **Sourcetype:** suricata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/adobe/coldfusion_cve_2023_29298.log


---

*Source: [Splunk Security Content](detections/web/adobe_coldfusion_access_control_bypass.yml)*
