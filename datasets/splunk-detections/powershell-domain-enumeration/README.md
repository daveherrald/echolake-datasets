# PowerShell Domain Enumeration

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the execution of PowerShell commands used for domain enumeration, such as `get-netdomaintrust` and `get-adgroupmember`. It leverages PowerShell Script Block Logging (EventCode=4104) to capture and analyze the full command sent to PowerShell. This activity is significant as it often indicates reconnaissance efforts by an attacker to map out the domain structure and identify key users and groups. If confirmed malicious, this behavior could lead to further targeted attacks, privilege escalation, and unauthorized access to sensitive information within the domain.

## MITRE ATT&CK

- T1059.001

## Analytic Stories

- Hermetic Wiper
- Malicious PowerShell
- CISA AA23-347A
- Data Destruction
- Interlock Ransomware
- Microsoft WSUS CVE-2025-59287

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/enumeration.log


---

*Source: [Splunk Security Content](detections/endpoint/powershell_domain_enumeration.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
