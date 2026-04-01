# Linux Auditd Preload Hijack Via Preload File

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting suspicious preload hijacking via the `preload` file, which may indicate an attacker's attempt to intercept or manipulate library loading processes.
The `preload` file can be used to force the loading of specific libraries before others, potentially allowing malicious code to execute or alter application behavior.
By monitoring for unusual or unauthorized modifications to the `preload` file, this analytic helps identify attempts to hijack preload mechanisms, enabling security teams to investigate and address potential threats to system integrity and security.
Correlate this with related EXECVE or PROCTITLE events to identify the process or user responsible for the access or modification.


## MITRE ATT&CK

- T1574.006

## Analytic Stories

- VoidLink Cloud-Native Linux Malware
- Linux Living Off The Land
- Linux Privilege Escalation
- Linux Persistence Techniques
- Compromised Linux Host

## Data Sources

- Linux Auditd Path
- Linux Auditd Cwd

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1574.006/auditd_path_preload_file/path_preload.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_preload_hijack_via_preload_file.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
