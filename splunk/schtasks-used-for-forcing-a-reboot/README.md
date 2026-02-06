# Schtasks used for forcing a reboot

**Type:** TTP

**Author:** Bhavin Patel, Splunk

## Description

The following analytic detects the use of 'schtasks.exe' to schedule forced system reboots using the 'shutdown' and '/create' flags. It leverages endpoint process data to identify instances where these specific command-line arguments are used. This activity is significant because it may indicate an adversary attempting to disrupt operations or force a reboot to execute further malicious actions. If confirmed malicious, this could lead to system downtime, potential data loss, and provide an attacker with an opportunity to execute additional payloads or evade detection.

## MITRE ATT&CK

- T1053.005

## Analytic Stories

- Windows Persistence Techniques
- Ransomware
- Scheduled Tasks

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/schtask_shutdown/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/schtasks_used_for_forcing_a_reboot.yml)*
