# Windows Impair Defense Disable Win Defender Gen reports

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects modifications in the Windows registry to disable Windows Defender generic reports. It leverages data from the Endpoint.Registry data model, specifically monitoring changes to the "DisableGenericRePorts" registry value. This activity is significant as it can prevent the transmission of error reports to Microsoft's Windows Error Reporting service, potentially hiding malicious activities. If confirmed malicious, this action could allow attackers to bypass Windows Defender detections, reducing the visibility of their activities and increasing the risk of undetected system compromise.

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

*Source: [Splunk Security Content](detections/endpoint/windows_impair_defense_disable_win_defender_gen_reports.yml)*
