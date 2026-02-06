# Linux Possible Ssh Key File Creation

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the creation of SSH key files in the ~/.ssh/ directory. It leverages filesystem data to identify new files in this specific path. This activity is significant because threat actors often create SSH keys to gain persistent access and escalate privileges on a compromised host. If confirmed malicious, this could allow attackers to remotely access the machine using the OpenSSH daemon service, leading to potential unauthorized control and data exfiltration.

## MITRE ATT&CK

- T1098.004

## Analytic Stories

- Linux Privilege Escalation
- Linux Persistence Techniques
- Linux Living Off The Land
- Hellcat Ransomware

## Data Sources

- Sysmon for Linux EventID 11

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.004/ssh_authorized_keys/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_possible_ssh_key_file_creation.yml)*
