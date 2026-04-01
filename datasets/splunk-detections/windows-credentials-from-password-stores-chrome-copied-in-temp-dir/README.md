# Windows Credentials from Password Stores Chrome Copied in TEMP Dir

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the copying of Chrome's Local State and Login Data files into temporary folders, a tactic often used by the Braodo stealer malware. These files contain encrypted user credentials, including saved passwords and login session details. The detection monitors for suspicious copying activity involving these specific Chrome files, particularly in temp directories where malware typically processes the stolen data. Identifying this behavior enables security teams to act quickly, preventing attackers from decrypting and exfiltrating sensitive browser credentials and mitigating the risk of unauthorized access.

## MITRE ATT&CK

- T1555.003

## Analytic Stories

- Braodo Stealer
- Scattered Lapsus$ Hunters

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1555.003/browser_credential_info_temp/braodo_browser_info.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_credentials_from_password_stores_chrome_copied_in_temp_dir.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
