# ConnectWise ScreenConnect Path Traversal Windows SACL

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting attempts to exploit the ConnectWise ScreenConnect CVE-2024-1708 vulnerability using Windows SACL EventCode 4663. It identifies path traversal attacks by monitoring file system events related to the ScreenConnect service. This activity is significant as it allows unauthorized access to sensitive files and directories, potentially leading to data exfiltration or arbitrary code execution. If confirmed malicious, attackers could gain unauthorized access to critical data or execute harmful code, compromising the integrity and security of the affected system. Immediate remediation by updating to version 23.9.8 or above is recommended.

## MITRE ATT&CK

- T1190

## Analytic Stories

- ConnectWise ScreenConnect Vulnerabilities
- Compromised Windows Host
- Seashell Blizzard

## Data Sources

- Windows Event Log Security 4663

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/screenconnect/4663_connectwise_aspx_app_extensions.log


---

*Source: [Splunk Security Content](detections/endpoint/connectwise_screenconnect_path_traversal_windows_sacl.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
