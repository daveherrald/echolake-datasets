# Linux Ingress Tool Transfer Hunting

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the use of 'curl' and 'wget' commands within a Linux environment. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names, user information, and command-line executions. This activity is significant as 'curl' and 'wget' are commonly used for downloading files, which can indicate potential ingress of malicious tools. If confirmed malicious, this activity could lead to unauthorized code execution, data exfiltration, or further compromise of the system. Monitoring and tuning this detection helps identify and differentiate between normal and potentially harmful usage.

## MITRE ATT&CK

- T1105

## Analytic Stories

- Ingress Tool Transfer
- Linux Living Off The Land
- XorDDos
- NPM Supply Chain Compromise

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1105/atomic_red_team/curl-linux-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_ingress_tool_transfer_hunting.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
