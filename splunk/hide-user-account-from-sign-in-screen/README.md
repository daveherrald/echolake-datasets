# Hide User Account From Sign-In Screen

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

The following analytic detects a suspicious registry modification that hides a user account from the Windows Login screen. It leverages data from the Endpoint.Registry data model, specifically monitoring changes to the registry path "*\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\Userlist*" with a value of "0x00000000". This activity is significant as it may indicate an adversary attempting to create a hidden admin account to avoid detection and maintain persistence on the compromised machine. If confirmed malicious, this could allow the attacker to maintain undetected access and control over the system, posing a severe security risk.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- XMRig
- Windows Registry Abuse
- Azorult
- Warzone RAT

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/hotkey_disabled_hidden_user/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/hide_user_account_from_sign_in_screen.yml)*
