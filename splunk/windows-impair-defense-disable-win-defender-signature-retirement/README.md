# Windows Impair Defense Disable Win Defender Signature Retirement

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects modifications to the Windows registry that disable Windows Defender Signature Retirement. It leverages data from the Endpoint.Registry data model, specifically monitoring changes to the DisableSignatureRetirement registry setting. This activity is significant because disabling signature retirement can prevent Windows Defender from removing outdated antivirus signatures, potentially reducing its effectiveness in detecting threats. If confirmed malicious, this action could allow an attacker to evade detection by using older, less relevant signatures, thereby compromising the system's security posture.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Windows Defense Evasion Tactics
- Windows Registry Abuse
- Scattered Lapsus$ Hunters

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/disable-windows-security-defender-features/windefender-bypas-2-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_impair_defense_disable_win_defender_signature_retirement.yml)*
