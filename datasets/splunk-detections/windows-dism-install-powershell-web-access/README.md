# Windows DISM Install PowerShell Web Access

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the installation of PowerShell Web Access using the Deployment Image Servicing and Management (DISM) tool. It leverages Sysmon EventID 1 to identify the execution of `dism.exe` with specific parameters related to enabling the WindowsPowerShellWebAccess feature. This activity is significant because enabling PowerShell Web Access can facilitate remote execution of PowerShell commands, potentially allowing an attacker to gain unauthorized access to systems and networks. If confirmed malicious, this action could lead to further exploitation and compromise of the affected system.

## MITRE ATT&CK

- T1548.002

## Analytic Stories

- CISA AA24-241A

## Data Sources

- Windows Event Log Security 4688
- Sysmon EventID 1

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.002/atomic_red_team/dism_pswa_4688_windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_dism_install_powershell_web_access.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
