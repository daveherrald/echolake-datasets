# Linux Add User Account

**Type:** Hunting

**Author:** Teoderick Contreras, Bhavin Patel, Splunk

## Description

This dataset contains sample data for detecting the creation of new user accounts on Linux systems using commands like "useradd" or "adduser." It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant as adversaries often create new user accounts to establish persistence on compromised hosts. If confirmed malicious, this could allow attackers to maintain access, escalate privileges, and further compromise the system, posing a severe security risk.

## MITRE ATT&CK

- T1136.001

## Analytic Stories

- Linux Privilege Escalation
- Linux Persistence Techniques
- Cisco Isovalent Suspicious Activity

## Data Sources

- Sysmon for Linux EventID 1
- Cisco Isovalent Process Exec

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.003/linux_adduser/sysmon_linux.log

- **Source:** not_applicable
  **Sourcetype:** cisco:isovalent:processExec
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_isovalent/cisco_isovalent.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_add_user_account.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
