# Allow Network Discovery In Firewall

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting a suspicious modification to the firewall to allow network discovery on a machine. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions involving the 'netsh' command to enable network discovery. This activity is significant because it is commonly used by ransomware, such as REvil and RedDot, to discover and compromise additional machines on the network. If confirmed malicious, this could lead to widespread file encryption across multiple hosts, significantly amplifying the impact of the ransomware attack.

## MITRE ATT&CK

- T1562.007

## Analytic Stories

- BlackByte Ransomware
- NjRAT
- Revil Ransomware
- Ransomware
- Medusa Ransomware
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

*Source: [Splunk Security Content](detections/endpoint/allow_network_discovery_in_firewall.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
