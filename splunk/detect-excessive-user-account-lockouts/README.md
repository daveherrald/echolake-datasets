# Detect Excessive User Account Lockouts

**Type:** Anomaly

**Author:** David Dorsey, Splunk

## Description

The following analytic identifies user accounts experiencing an excessive number of lockouts within a short timeframe. It leverages the 'Change' data model, specifically focusing on events where the result indicates a lockout. This activity is significant as it may indicate a brute-force attack or misconfiguration, both of which require immediate attention. If confirmed malicious, this behavior could lead to account compromise, unauthorized access, and potential lateral movement within the network.

## MITRE ATT&CK

- T1078.003

## Analytic Stories

- Active Directory Password Spraying
- Scattered Lapsus$ Hunters

## Data Sources


## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.002/account_lockout/windows-xml-1.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_excessive_user_account_lockouts.yml)*
