# Linux Doas Conf File Creation

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the creation of the doas.conf file on a Linux host. This file is used by the doas utility to allow standard users to perform tasks as root, similar to sudo. The detection leverages filesystem data from the Endpoint data model, focusing on the creation of the doas.conf file. This activity is significant because it can indicate an attempt to gain elevated privileges, potentially by an adversary. If confirmed malicious, this could allow an attacker to execute commands with root privileges, leading to full system compromise.

## MITRE ATT&CK

- T1548.003

## Analytic Stories

- Linux Privilege Escalation
- Linux Persistence Techniques

## Data Sources

- Sysmon for Linux EventID 11

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.003/doas/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_doas_conf_file_creation.yml)*
