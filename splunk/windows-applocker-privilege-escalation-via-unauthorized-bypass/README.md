# Windows AppLocker Privilege Escalation via Unauthorized Bypass

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic utilizes Windows AppLocker event logs to identify attempts to bypass application restrictions. AppLocker is a feature that allows administrators to specify which applications are permitted to run on a system. This analytic is designed to identify attempts to bypass these restrictions, which could be indicative of an attacker attempting to escalate privileges. The analytic uses EventCodes 8007, 8004, 8022, 8025, 8029, and 8040 to identify these attempts. The analytic will identify the host, full file path, and target user associated with the bypass attempt. These EventCodes are related to block events and focus on 5 attempts or more.

## MITRE ATT&CK

- T1218

## Analytic Stories

- Windows AppLocker

## Data Sources


## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-AppLocker/MSI and Script
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562/applocker/applocker.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_applocker_privilege_escalation_via_unauthorized_bypass.yml)*
