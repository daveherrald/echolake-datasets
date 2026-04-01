# Windows Credentials Access via VaultCli Module

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting potentially abnormal interactions with VaultCLI.dll, particularly those initiated by processes located in publicly writable Windows folder paths. The VaultCLI.dll module allows processes to extract credentials from the Windows Credential Vault. It was seen being abused by information stealers such as Meduza. The analytic monitors suspicious API calls, unauthorized credential access patterns, and anomalous process behaviors indicative of malicious activity. By leveraging a combination of signature-based detection and behavioral analysis, it effectively flags attempts to misuse the vault for credential theft, enabling swift response to protect sensitive user data and ensure system security.

## MITRE ATT&CK

- T1555.004

## Analytic Stories

- Meduza Stealer
- Hellcat Ransomware

## Data Sources

- Sysmon EventID 7

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1555.004/vaultcli_creds/vaultcli.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_credentials_access_via_vaultcli_module.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
