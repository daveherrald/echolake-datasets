# Windows Impair Defense Disable Win Defender Report Infection

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects modifications to the Windows registry that disable Windows Defender's infection reporting. It leverages data from the Endpoint.Registry datamodel, specifically monitoring changes to the "DontReportInfectionInformation" registry key. This activity is significant because it can prevent Windows Defender from reporting detailed threat information to Microsoft, potentially allowing malware to evade detection. If confirmed malicious, this action could enable attackers to bypass security measures, maintain persistence, and avoid detection, leading to prolonged unauthorized access and potential data breaches.

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

*Source: [Splunk Security Content](detections/endpoint/windows_impair_defense_disable_win_defender_report_infection.yml)*
