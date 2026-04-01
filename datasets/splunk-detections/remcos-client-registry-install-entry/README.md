# Remcos client registry install entry

**Type:** TTP

**Author:** Steven Dick, Bhavin Patel, Rod Soto, Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the presence of a registry key associated with the Remcos RAT agent on a host. It leverages data from the Endpoint.Processes and Endpoint.Registry data models in Splunk, focusing on instances where the "license" key is found in the "Software\Remcos" path. This behavior is significant as it indicates potential compromise by the Remcos RAT, a remote access Trojan used for unauthorized access and data exfiltration. If confirmed malicious, the attacker could gain control over the system, steal sensitive information, or use the compromised host for further attacks. Immediate investigation and remediation are required.

## MITRE ATT&CK

- T1112

## Analytic Stories

- Remcos
- Windows Registry Abuse

## Data Sources

- Sysmon EventID 12
- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/remcos/remcos_registry/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/remcos_client_registry_install_entry.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
