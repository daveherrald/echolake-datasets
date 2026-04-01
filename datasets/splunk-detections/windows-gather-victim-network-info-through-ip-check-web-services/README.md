# Windows Gather Victim Network Info Through Ip Check Web Services

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting processes attempting to connect to known IP check web services. This behavior is identified using Sysmon EventCode 22 logs, specifically monitoring DNS queries to services like "wtfismyip.com" and "ipinfo.io". This activity is significant as it is commonly used by malware, such as Trickbot, for reconnaissance to determine the infected machine's IP address. If confirmed malicious, this could allow attackers to gather network information, aiding in further attacks or lateral movement within the network.

## MITRE ATT&CK

- T1590.005

## Analytic Stories

- Azorult
- DarkCrystal RAT
- Phemedrone Stealer
- Snake Keylogger
- Handala Wiper
- PXA Stealer
- Meduza Stealer
- Water Gamayun
- Quasar RAT
- 0bj3ctivity Stealer
- Castle RAT

## Data Sources

- Sysmon EventID 22

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/azorult/sysmon.log


---

*Source: [Splunk Security Content](detections/network/windows_gather_victim_network_info_through_ip_check_web_services.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
