# Allow File And Printing Sharing In Firewall

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the modification of firewall settings to allow file and printer sharing. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions involving 'netsh' commands that enable file and printer sharing. This activity is significant because it can indicate an attempt by ransomware to discover and encrypt files on additional machines connected to the compromised host. If confirmed malicious, this could lead to widespread file encryption across the network, significantly increasing the impact of a ransomware attack.

## MITRE ATT&CK

- T1562.007

## Analytic Stories

- Ransomware
- BlackByte Ransomware
- Hellcat Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ransomware_ttp/data2/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/allow_file_and_printing_sharing_in_firewall.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
