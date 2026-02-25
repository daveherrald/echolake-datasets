# Modify ACL permission To Files Or Folder

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the modification of ACL permissions to files or folders, making them accessible to everyone or to system account. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on processes like "cacls.exe," "icacls.exe," and "xcacls.exe" with specific command-line arguments. This activity is significant as it may indicate an adversary attempting to evade ACLs or access protected files. If confirmed malicious, this could allow unauthorized access to sensitive data, potentially leading to data breaches or further system compromise.

## MITRE ATT&CK

- T1222

## Analytic Stories

- Crypto Stealer
- XMRig
- Defense Evasion or Unauthorized Access Via SDDL Tampering

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/modify_acl_permission_to_files_or_folder.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
