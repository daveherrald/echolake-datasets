# Attacker Tools On Endpoint

**Type:** TTP

**Author:** Bhavin Patel, Splunk, sventec, Github Community

## Description

This dataset contains sample data for detecting the execution of tools commonly exploited by cybercriminals, such as those used for unauthorized access, network scanning, or data exfiltration. It leverages process activity data from Endpoint Detection and Response (EDR) agents, focusing on known attacker tool names. This activity is significant because it serves as an early warning system for potential security incidents, enabling prompt response. If confirmed malicious, this activity could lead to unauthorized access, data theft, or further network compromise, posing a severe threat to the organization's security infrastructure.

## MITRE ATT&CK

- T1003
- T1036.005
- T1595

## Analytic Stories

- XMRig
- Unusual Processes
- SamSam Ransomware
- CISA AA22-264A
- Compromised Windows Host
- PHP-CGI RCE Attack on Japanese Organizations
- Cisco Network Visibility Module Analytics
- Scattered Spider

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2
- Cisco Network Visibility Module Flow Data

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1595/attacker_scan_tools/windows-sysmon.log

- **Source:** not_applicable
  **Sourcetype:** cisco:nvm:flowdata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_network_visibility_module/cisco_nvm_flowdata/nvm_flowdata.log


---

*Source: [Splunk Security Content](detections/endpoint/attacker_tools_on_endpoint.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
