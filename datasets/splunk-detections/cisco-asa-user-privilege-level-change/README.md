# Cisco ASA - User Privilege Level Change

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This analytic detects privilege level changes for user accounts on Cisco ASA devices via CLI or ASDM.
Adversaries may escalate account privileges to gain elevated access to network infrastructure, enable additional command execution capabilities, or establish higher-level persistent access. Privilege levels on Cisco ASA range from 0 (lowest) to 15 (full administrative access), with level 15 providing complete device control.
The detection monitors for ASA message ID 502103, which is generated whenever a user account's privilege level is modified, capturing both the old and new privilege levels along with the username and administrator who made the change.
Investigate unexpected privilege changes, especially escalations to level 15, substantial privilege increases (e.g., from level 1 to 15), changes performed outside business hours, changes by non-administrative users, or changes without corresponding change management tickets.


## MITRE ATT&CK

- T1078.003
- T1098

## Analytic Stories

- Suspicious Cisco Adaptive Security Appliance Activity
- ArcaneDoor

## Data Sources

- Cisco ASA Logs

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:asa
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_asa/generic/cisco_asa_generic_logs.log


---

*Source: [Splunk Security Content](detections/application/cisco_asa___user_privilege_level_change.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
