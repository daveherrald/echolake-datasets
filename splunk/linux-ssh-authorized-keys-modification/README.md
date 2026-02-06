# Linux SSH Authorized Keys Modification

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the modification of SSH Authorized Keys on Linux systems. It leverages process execution data from Endpoint Detection and Response (EDR) agents, specifically monitoring commands like "bash" and "cat" interacting with "authorized_keys" files. This activity is significant as adversaries often modify SSH Authorized Keys to establish persistent access to compromised endpoints. If confirmed malicious, this behavior could allow attackers to maintain unauthorized access, bypassing traditional authentication mechanisms and potentially leading to further exploitation or data exfiltration.

## MITRE ATT&CK

- T1098.004

## Analytic Stories

- Linux Living Off The Land
- Hellcat Ransomware
- VoidLink Cloud-Native Linux Malware

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.004/ssh_authorized_keys/authkey_linux-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_ssh_authorized_keys_modification.yml)*
