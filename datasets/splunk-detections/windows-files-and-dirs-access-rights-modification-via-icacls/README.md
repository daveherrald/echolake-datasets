# Windows Files and Dirs Access Rights Modification Via Icacls

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying the modification of security permissions
on files or directories using tools like icacls.exe, cacls.exe, or xcacls.exe. It
leverages data from Endpoint Detection and Response (EDR) agents, focusing on specific
command-line executions. This activity is significant as it is commonly used by
Advanced Persistent Threats (APTs) and coinminer scripts to evade detection and
maintain control over compromised systems. If confirmed malicious, this behavior
could allow attackers to hinder investigation, impede remediation efforts, and maintain
persistent access to the compromised environment.


## MITRE ATT&CK

- T1222.001

## Analytic Stories

- Amadey
- Defense Evasion or Unauthorized Access Via SDDL Tampering

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/amadey/access_permission/amadey_sysmon2.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_files_and_dirs_access_rights_modification_via_icacls.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
