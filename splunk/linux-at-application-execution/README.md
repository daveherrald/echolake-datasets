# Linux At Application Execution

**Type:** Anomaly

**Author:** Teoderick Contreras, Bhavin Patel, Splunk

## Description

The following analytic detects the execution of the "At" application in Linux, which can be used by attackers to create persistence entries on a compromised host. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and parent process names associated with "at" or "atd". This activity is significant because the "At" application can be exploited to maintain unauthorized access or deliver additional malicious payloads. If confirmed malicious, this behavior could lead to data theft, ransomware attacks, or other severe consequences. Immediate investigation is required to determine the legitimacy of the execution and mitigate potential risks.

## MITRE ATT&CK

- T1053.002

## Analytic Stories

- Linux Privilege Escalation
- Linux Persistence Techniques
- Linux Living Off The Land
- Scheduled Tasks
- Cisco Isovalent Suspicious Activity

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.002/at_execution/sysmon_linux.log

- **Source:** not_applicable
  **Sourcetype:** cisco:isovalent:processExec
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_isovalent/cisco_isovalent.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_at_application_execution.yml)*
