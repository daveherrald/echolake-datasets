# Linux Auditd Preload Hijack Library Calls

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the use of the LD_PRELOAD environment variable to hijack or hook library functions on a Linux platform. It leverages data from Linux Auditd, focusing on process execution logs that include command-line details. This activity is significant because adversaries, malware authors, and red teamers commonly use this technique to gain elevated privileges and establish persistence on a compromised machine. If confirmed malicious, this behavior could allow attackers to execute arbitrary code, escalate privileges, and maintain long-term access to the system.

## MITRE ATT&CK

- T1574.006

## Analytic Stories

- Linux Persistence Techniques
- Compromised Linux Host
- China-Nexus Threat Activity
- Salt Typhoon
- Linux Privilege Escalation

## Data Sources

- Linux Auditd Execve

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1574.006/linux_auditd_ldpreload/auditd_execve_ldpreload.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_preload_hijack_library_calls.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
