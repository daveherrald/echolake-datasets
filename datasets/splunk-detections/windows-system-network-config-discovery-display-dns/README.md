# Windows System Network Config Discovery Display DNS

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying the execution of the "ipconfig /displaydns" command, which retrieves DNS reply information using the built-in Windows tool IPConfig. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process command-line executions. Monitoring this activity is significant as threat actors and post-exploitation tools like WINPEAS often abuse this command to gather network information. If confirmed malicious, this activity could allow attackers to map the network, identify DNS servers, and potentially facilitate further network-based attacks or lateral movement.

## MITRE ATT&CK

- T1016

## Analytic Stories

- Medusa Ransomware
- Windows Post-Exploitation
- Prestige Ransomware
- Water Gamayun

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/winpeas/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_system_network_config_discovery_display_dns.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
