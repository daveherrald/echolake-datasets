# Windows Remote Desktop Network Bruteforce Attempt

**Type:** Anomaly

**Author:** Jose Hernandez, Bhavin Patel, Splunk

## Description

This dataset contains sample data for identifying potential Remote Desktop Protocol (RDP) brute force attacks by monitoring network traffic for RDP application activity. This query detects potential RDP brute force attacks by identifying source IPs that have made more than 10 connection attempts to the same RDP port on a host within a one-hour window. The results are presented in a table that includes the source and destination IPs, destination port, number of attempts, and the times of the first and last connection attempts, helping to prioritize IPs based on the intensity of activity.

## MITRE ATT&CK

- T1110.001

## Analytic Stories

- SamSam Ransomware
- Ryuk Ransomware
- Compromised User Account
- Windows RDP Artifacts and Defense Evasion

## Data Sources

- Sysmon EventID 3

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.001/rdp_brute_sysmon/sysmon.log


---

*Source: [Splunk Security Content](detections/network/windows_remote_desktop_network_bruteforce_attempt.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
