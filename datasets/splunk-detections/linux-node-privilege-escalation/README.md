# Linux Node Privilege Escalation

**Type:** Anomaly

**Author:** Gowthamaraj Rajendran, Splunk

## Description

This dataset contains sample data for identifying the execution of Node.js with elevated privileges using sudo, specifically when spawning child processes. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions that include specific Node.js commands. This activity is significant because running Node.js as a superuser without dropping privileges can allow unauthorized access to the file system and potential privilege escalation. If confirmed malicious, this could enable an attacker to maintain privileged access, execute arbitrary code, and compromise sensitive data within the environment.

## MITRE ATT&CK

- T1548.003

## Analytic Stories

- Linux Privilege Escalation
- Linux Living Off The Land

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/node/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_node_privilege_escalation.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
