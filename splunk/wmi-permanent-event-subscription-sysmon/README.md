# WMI Permanent Event Subscription - Sysmon

**Type:** TTP

**Author:** Rico Valdez, Michael Haag, Splunk

## Description

The following analytic identifies the creation of WMI permanent event subscriptions, which can be used to establish persistence or perform privilege escalation. It leverages Sysmon data, specifically EventCodes 19, 20, and 21, to detect the creation of WMI EventFilters, EventConsumers, and FilterToConsumerBindings. This activity is significant as it may indicate an attacker setting up mechanisms to execute code with elevated SYSTEM privileges when specific events occur. If confirmed malicious, this could allow the attacker to maintain persistence, escalate privileges, and execute arbitrary code, posing a severe threat to the environment.

## MITRE ATT&CK

- T1546.003

## Analytic Stories

- Suspicious WMI Use

## Data Sources

- Sysmon EventID 21

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.003/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/wmi_permanent_event_subscription___sysmon.yml)*
