# Windows Mimikatz Crypto Export File Extensions

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the creation of files with extensions commonly associated with the Mimikatz Crypto module. It leverages the Endpoint.Filesystem data model to identify specific file names indicative of certificate export activities. This behavior is significant as it may indicate the use of Mimikatz to export cryptographic keys, which is a common tactic for credential theft. If confirmed malicious, this activity could allow an attacker to exfiltrate sensitive cryptographic material, potentially leading to unauthorized access and further compromise of the environment.

## MITRE ATT&CK

- T1649

## Analytic Stories

- Sandworm Tools
- CISA AA23-347A
- Windows Certificate Services

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1649/atomic_red_team/certwrite_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_mimikatz_crypto_export_file_extensions.yml)*
