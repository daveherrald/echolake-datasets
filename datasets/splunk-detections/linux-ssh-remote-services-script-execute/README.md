# Linux SSH Remote Services Script Execute

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the use of SSH to move laterally and execute a script or file on a remote host. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on specific SSH command-line parameters and URLs. This activity is significant as it may indicate an attacker attempting to execute remote commands or scripts, potentially leading to unauthorized access or control over additional systems. If confirmed malicious, this could result in lateral movement, privilege escalation, or the execution of malicious payloads, compromising the security of the network.

## MITRE ATT&CK

- T1021.004

## Analytic Stories

- Linux Living Off The Land
- Hellcat Ransomware
- VoidLink Cloud-Native Linux Malware

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.004/atomic_red_team/linux-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_ssh_remote_services_script_execute.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
