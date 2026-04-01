# Linux pkexec Privilege Escalation

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the execution of `pkexec` without any command-line arguments. This behavior leverages data from Endpoint Detection and Response (EDR) agents, focusing on process telemetry. The significance lies in the fact that this pattern is associated with the exploitation of CVE-2021-4034 (PwnKit), a critical vulnerability in Polkit's pkexec component. If confirmed malicious, this activity could allow an attacker to gain full root privileges on the affected Linux system, leading to complete system compromise and potential unauthorized access to sensitive information.

## MITRE ATT&CK

- T1068

## Analytic Stories

- Linux Privilege Escalation
- Linux Living Off The Land

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1068/pkexec/linux-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_pkexec_privilege_escalation.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
