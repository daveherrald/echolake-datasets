# Creation of Shadow Copy with wmic and powershell

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic detects the creation of shadow copies using "wmic" or "Powershell" commands. It leverages the Endpoint.Processes data model in Splunk to identify processes where the command includes "shadowcopy" and "create". This activity is significant because it may indicate an attacker attempting to manipulate or access data in an unauthorized manner, potentially leading to data theft or manipulation. If confirmed malicious, this behavior could allow attackers to backup and exfiltrate sensitive data or hide their tracks by restoring files to a previous state after an attack.

## MITRE ATT&CK

- T1003.003

## Analytic Stories

- Volt Typhoon
- Living Off The Land
- Compromised Windows Host
- Credential Dumping

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.003/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/creation_of_shadow_copy_with_wmic_and_powershell.yml)*
