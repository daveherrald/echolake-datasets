# Windows Impair Defense Change Win Defender Health Check Intervals

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects modifications to the Windows registry that change the health check interval of Windows Defender. It leverages data from the Endpoint datamodel, specifically monitoring changes to the "ServiceKeepAlive" registry path with a value of "0x00000001". This activity is significant because altering Windows Defender settings can impair its ability to perform timely health checks, potentially leaving the system vulnerable. If confirmed malicious, this could allow an attacker to disable or delay security scans, increasing the risk of undetected malware or other malicious activities.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Windows Defense Evasion Tactics
- Windows Registry Abuse

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/disable-windows-security-defender-features/windefender-bypas-2-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_impair_defense_change_win_defender_health_check_intervals.yml)*
