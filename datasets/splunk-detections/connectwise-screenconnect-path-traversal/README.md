# ConnectWise ScreenConnect Path Traversal

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting attempts to exploit the ConnectWise ScreenConnect CVE-2024-1708 vulnerability, which allows path traversal attacks by manipulating file_path and file_name parameters in the URL. It leverages the Endpoint datamodel Filesystem node to identify suspicious file system events, specifically targeting paths and filenames associated with ScreenConnect. This activity is significant as it can lead to unauthorized access to sensitive files and directories, potentially resulting in data exfiltration or arbitrary code execution. If confirmed malicious, attackers could gain unauthorized access and control over the host system, posing a severe security risk.

## MITRE ATT&CK

- T1190

## Analytic Stories

- ConnectWise ScreenConnect Vulnerabilities
- Seashell Blizzard

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/screenconnect/sysmon_app_extensions.log


---

*Source: [Splunk Security Content](detections/endpoint/connectwise_screenconnect_path_traversal.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
