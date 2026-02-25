# Detect Remote Access Software Usage File

**Type:** Anomaly

**Author:** Steven Dick

## Description

This dataset contains sample data for detecting the writing of files from known remote access software to disk within the environment.
It leverages data from Endpoint Detection and Response (EDR) agents, focusing on file path, file name, and user information.
This activity is significant as adversaries often use remote access tools like AnyDesk, GoToMyPC, LogMeIn, and TeamViewer to maintain unauthorized access.
If confirmed malicious, this could allow attackers to persist in the environment, potentially leading to data exfiltration, further compromise, or complete control over affected systems.
It is best to update both the remote_access_software_usage_exception.csv lookup and the remote_access_software lookup with any known or approved remote access software to reduce false positives and increase coverage.
In order to enhance performance, the detection filters for specific file names extensions / names that are used in the remote_access_software lookup.
If add additional entries, consider updating the search filters to include those file names / extensions as well, if not alread covered.


## MITRE ATT&CK

- T1219

## Analytic Stories

- Cactus Ransomware
- CISA AA24-241A
- Command And Control
- GhostRedirector IIS Module and Rungan Backdoor
- Gozi Malware
- Insider Threat
- Interlock Ransomware
- Ransomware
- Remote Monitoring and Management Software
- Scattered Lapsus$ Hunters
- Scattered Spider
- Seashell Blizzard

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1219/screenconnect/screenconnect_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_remote_access_software_usage_file.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
