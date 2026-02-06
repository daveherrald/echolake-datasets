# Windows Unsecured Outlook Credentials Access In Registry

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects unauthorized access to Outlook credentials stored in the Windows registry. It leverages Windows Security Event logs, specifically EventCode 4663, to identify access attempts to registry paths associated with Outlook profiles. This activity is significant as it may indicate attempts to steal sensitive email credentials, which could lead to unauthorized access to email accounts. If confirmed malicious, this could allow attackers to exfiltrate sensitive information, impersonate users, or execute further unauthorized actions within Outlook, posing a significant security risk.

## MITRE ATT&CK

- T1552

## Analytic Stories

- StealC Stealer
- Snake Keylogger
- Meduza Stealer
- 0bj3ctivity Stealer
- Lokibot

## Data Sources

- Windows Event Log Security 4663

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1552/snakey_keylogger_outlook_reg_access/snakekeylogger_4663.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_unsecured_outlook_credentials_access_in_registry.yml)*
