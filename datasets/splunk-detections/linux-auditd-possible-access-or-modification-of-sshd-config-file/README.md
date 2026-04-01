# Linux Auditd Possible Access Or Modification Of Sshd Config File

**Type:** Anomaly

**Author:** Teoderick Contreras, Nasreddine Bencherchali, Splunk

## Description

This dataset contains sample data for detecting access, deletion or modification of the ssh_config file on Linux systems.
It leverages data from Linux Auditd, focusing on events of type PATH with a nametype of ("NORMAL", "CREATE", "DELETE").
This activity could be significant because unauthorized changes to ssh_config can allow threat actors to redirect port connections or use unauthorized keys, potentially compromising the system.
Correlate this with related EXECVE or PROCTITLE events to identify the process or user responsible for the access or modification.
If confirmed malicious, this could lead to unauthorized access, privilege escalation, or persistent backdoor access, posing a severe security risk.


## MITRE ATT&CK

- T1098.004

## Analytic Stories

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.004/auditd_path_ssh_config/path_ssh_config.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_possible_access_or_modification_of_sshd_config_file.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
