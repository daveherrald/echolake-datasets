# MacOS AMOS Stealer - Virtual Machine Check Activity

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk, Alex Karkins

## Description

This dataset contains sample data for detecting AMOS Stealer VM check activity on macOS. It leverages osquery to monitor process events and identifies the execution of the "osascript" command along with specific commandline strings. This activity is significant
as AMOS stealer was seen using this pattern in order to check if the host is a Virtual Machine or not. If confirmed malicious, this behavior indicate that the host is already infected by the AMOS stealer, which could allow attackers to execute arbitrary code, escalate privileges, steal information, or persist within the environment, posing a significant security risk.


## MITRE ATT&CK

- T1059.002

## Analytic Stories

- AMOS Stealer
- Hellcat Ransomware

## Data Sources

- osquery

## Sample Data

- **Source:** osquery
  **Sourcetype:** osquery:results
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.002/amos_stealer/amos_stealer.log


---

*Source: [Splunk Security Content](detections/endpoint/macos_amos_stealer___virtual_machine_check_activity.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
