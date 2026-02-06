# Linux Data Destruction Command

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of a Unix shell command designed to wipe root directories on a Linux host. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on the 'rm' command with force recursive deletion and the '--no-preserve-root' option. This activity is significant as it indicates potential data destruction attempts, often associated with malware like Awfulshred. If confirmed malicious, this behavior could lead to severe data loss, system instability, and compromised integrity of the affected Linux host. Immediate investigation and response are crucial to mitigate potential damage.

## MITRE ATT&CK

- T1485

## Analytic Stories

- AwfulShred
- Data Destruction

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/awfulshred/test1/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_data_destruction_command.yml)*
