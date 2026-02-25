# Windows Office Product Spawned MSDT

**Type:** TTP

**Author:** Michael Haag, Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting a Microsoft Office product spawning the Windows msdt.exe process. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process creation events where Office applications are the parent process. This activity is significant as it may indicate an attempt to exploit protocol handlers to bypass security controls, even if macros are disabled. If confirmed malicious, this behavior could allow an attacker to execute arbitrary code, potentially leading to system compromise, data exfiltration, or further lateral movement within the network.

## MITRE ATT&CK

- T1566.001

## Analytic Stories

- Spearphishing Attachments
- Compromised Windows Host
- Microsoft Support Diagnostic Tool Vulnerability CVE-2022-30190

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/macro/msdt.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_office_product_spawned_msdt.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
