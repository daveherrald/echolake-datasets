# Gsuite Drive Share In External Email

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects Google Drive or Google Docs files shared externally from an internal domain. It leverages GSuite Drive logs, extracting and comparing the source and destination email domains to identify external sharing. This activity is significant as it may indicate potential data exfiltration by an attacker or insider. If confirmed malicious, this could lead to unauthorized access to sensitive information, data leakage, and potential compliance violations. Monitoring this behavior helps in early detection and mitigation of data breaches.

## MITRE ATT&CK

- T1567.002

## Analytic Stories

- Scattered Lapsus$ Hunters
- Dev Sec Ops
- Insider Threat

## Data Sources

- G Suite Drive

## Sample Data

- **Source:** http:gsuite
  **Sourcetype:** gws:reports:drive
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1567.002/gsuite_share_drive/gdrive_share_external.log


---

*Source: [Splunk Security Content](detections/cloud/gsuite_drive_share_in_external_email.yml)*
