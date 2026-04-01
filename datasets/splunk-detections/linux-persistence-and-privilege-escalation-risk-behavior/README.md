# Linux Persistence and Privilege Escalation Risk Behavior

**Type:** Correlation

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying potential Linux persistence and privilege escalation activities. It leverages risk scores and event counts from various Linux-related data sources, focusing on tactics associated with persistence and privilege escalation. This activity is significant for a SOC because it highlights behaviors that could allow an attacker to maintain access or gain elevated privileges on a Linux system. If confirmed malicious, this activity could enable an attacker to execute code with higher privileges, persist in the environment, and potentially access sensitive information, posing a severe security risk.

## MITRE ATT&CK

- T1548

## Analytic Stories

- Linux Privilege Escalation
- Linux Persistence Techniques

## Data Sources


## Sample Data

- **Source:** linuxrisk
  **Sourcetype:** stash
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/linux_risk/linuxrisk.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_persistence_and_privilege_escalation_risk_behavior.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
