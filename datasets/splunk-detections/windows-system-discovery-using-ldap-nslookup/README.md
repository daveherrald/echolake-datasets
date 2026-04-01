# Windows System Discovery Using ldap Nslookup

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the execution of nslookup.exe to query domain information using LDAP. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line arguments. This activity is significant as nslookup.exe can be abused by malware like Qakbot to gather critical domain details, such as SRV records and server names. If confirmed malicious, this behavior could allow attackers to map the network, identify key servers, and plan further attacks, potentially leading to data exfiltration or lateral movement within the network.

## MITRE ATT&CK

- T1033

## Analytic Stories

- Qakbot

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1033/qakbot_discovery_cmdline/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_system_discovery_using_ldap_nslookup.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
