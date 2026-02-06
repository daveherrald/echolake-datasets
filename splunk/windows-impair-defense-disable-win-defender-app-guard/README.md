# Windows Impair Defense Disable Win Defender App Guard

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects modifications to the Windows registry that disable Windows Defender Application Guard auditing. It leverages data from the Endpoint.Registry data model, focusing on specific registry paths and values. This activity is significant because disabling auditing can hinder security monitoring and threat detection within the isolated environment, making it easier for malicious activities to go unnoticed. If confirmed malicious, this action could allow attackers to bypass Windows Defender protections, potentially leading to unauthorized access, data exfiltration, or further system compromise.

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

*Source: [Splunk Security Content](detections/endpoint/windows_impair_defense_disable_win_defender_app_guard.yml)*
