# Detect WMI Event Subscription Persistence

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying the creation of WMI Event Subscriptions, which can be used to establish persistence or perform privilege escalation. It detects EventID 19 (EventFilter creation), EventID 20 (EventConsumer creation), and EventID 21 (FilterToConsumerBinding creation) from Sysmon logs. This activity is significant because WMI Event Subscriptions can execute code with elevated SYSTEM privileges, making it a powerful persistence mechanism. If confirmed malicious, an attacker could maintain long-term access, escalate privileges, and execute arbitrary code, posing a severe threat to the environment.

## MITRE ATT&CK

- T1546.003

## Analytic Stories

- Suspicious WMI Use
- Hellcat Ransomware

## Data Sources

- Sysmon EventID 20

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.003/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_wmi_event_subscription_persistence.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
