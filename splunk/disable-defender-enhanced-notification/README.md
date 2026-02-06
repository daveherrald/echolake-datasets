# Disable Defender Enhanced Notification

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

The following analytic detects the modification of the registry to disable Windows Defender's Enhanced Notification feature. It leverages data from Endpoint Detection and Response (EDR) agents, specifically monitoring changes to the registry path associated with Windows Defender reporting. This activity is significant because disabling Enhanced Notifications can prevent users and administrators from receiving critical security alerts, potentially allowing malicious activities to go unnoticed. If confirmed malicious, this action could enable an attacker to bypass detection mechanisms, maintain persistence, and escalate their activities without triggering alerts.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Azorult
- CISA AA23-347A
- IcedID
- Windows Registry Abuse

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/disable_av/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/disable_defender_enhanced_notification.yml)*
