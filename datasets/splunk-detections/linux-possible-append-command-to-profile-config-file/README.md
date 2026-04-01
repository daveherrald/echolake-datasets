# Linux Possible Append Command To Profile Config File

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting suspicious command-lines that modify user profile files to automatically execute scripts or executables upon system reboot. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions involving profile files like ~/.bashrc and /etc/profile. This activity is significant as it indicates potential persistence mechanisms used by adversaries to maintain access to compromised hosts. If confirmed malicious, this could allow attackers to execute arbitrary code upon reboot, leading to persistent control over the system and potential further exploitation.

## MITRE ATT&CK

- T1546.004

## Analytic Stories

- Linux Privilege Escalation
- Linux Persistence Techniques

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.004/linux_init_profile/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_possible_append_command_to_profile_config_file.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
