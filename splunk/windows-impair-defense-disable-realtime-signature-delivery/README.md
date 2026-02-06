# Windows Impair Defense Disable Realtime Signature Delivery

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects modifications to the Windows registry that disable the Windows Defender real-time signature delivery feature. It leverages data from the Endpoint.Registry data model, specifically monitoring changes to the registry path associated with Windows Defender signature updates. This activity is significant because disabling real-time signature delivery can prevent Windows Defender from receiving timely malware definitions, reducing its effectiveness. If confirmed malicious, this action could allow attackers to bypass malware detection, leading to potential system compromise and persistent threats.

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

*Source: [Splunk Security Content](detections/endpoint/windows_impair_defense_disable_realtime_signature_delivery.yml)*
