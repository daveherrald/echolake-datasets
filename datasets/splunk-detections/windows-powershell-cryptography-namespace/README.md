# Windows Powershell Cryptography Namespace

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting suspicious PowerShell script execution involving the cryptography namespace via EventCode 4104. It leverages PowerShell Script Block Logging to identify scripts using cryptographic functions, excluding common hashes like SHA and MD5. This activity is significant as it is often associated with malware that decrypts or decodes additional malicious payloads. If confirmed malicious, this could allow an attacker to execute further code, escalate privileges, or establish persistence within the environment. Analysts should investigate the parent process, decrypted data, network connections, and the user executing the script.

## MITRE ATT&CK

- T1059.001

## Analytic Stories

- AsyncRAT
- XWorm

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/asyncrat_crypto_pwh_namespace/windows-powershell-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_powershell_cryptography_namespace.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
