# O365 PST export alert

**Type:** TTP

**Author:** Rod Soto, Splunk

## Description

The following analytic detects instances where a user has initiated an eDiscovery search or exported a PST file in an Office 365 environment. It leverages Office 365 management activity logs, specifically filtering for events under ThreatManagement with the name "eDiscovery search started or exported." This activity is significant as it may indicate data exfiltration attempts or unauthorized access to sensitive information. If confirmed malicious, it suggests an attacker or insider threat is attempting to gather or exfiltrate data, potentially leading to data breaches, loss of intellectual property, or unauthorized access to confidential communications. Immediate investigation is required.

## MITRE ATT&CK

- T1114

## Analytic Stories

- Office 365 Collection Techniques
- Data Exfiltration

## Data Sources

- O365

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1114/o365_export_pst_file/o365_export_pst_file.json


---

*Source: [Splunk Security Content](detections/cloud/o365_pst_export_alert.yml)*
