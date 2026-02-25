# Linux Setuid Using Setcap Utility

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the execution of the 'setcap' utility to enable the SUID bit on Linux systems. It leverages Endpoint Detection and Response (EDR) data, focusing on process names and command-line arguments that indicate the use of 'setcap' with specific capabilities. This activity is significant because setting the SUID bit allows a user to temporarily gain root access, posing a substantial security risk. If confirmed malicious, an attacker could escalate privileges, execute arbitrary commands with elevated permissions, and potentially compromise the entire system.

## MITRE ATT&CK

- T1548.001

## Analytic Stories

- Linux Privilege Escalation
- Linux Persistence Techniques

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.001/linux_setcap/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_setuid_using_setcap_utility.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
