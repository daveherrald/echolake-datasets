# Disable Windows Behavior Monitoring

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

This dataset contains sample data for identifying modifications in the registry to disable Windows Defender's real-time behavior monitoring. It leverages data from the Endpoint.Registry data model, specifically monitoring changes to registry paths associated with Windows Defender settings. This activity is significant because disabling real-time protection is a common tactic used by malware such as RATs, bots, or Trojans to evade detection. If confirmed malicious, this action could allow an attacker to execute code, escalate privileges, or persist in the environment without being detected by antivirus software.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Windows Defense Evasion Tactics
- CISA AA23-347A
- Revil Ransomware
- Azorult
- Windows Registry Abuse
- Black Basta Ransomware
- Ransomware
- RedLine Stealer
- Cactus Ransomware
- Scattered Lapsus$ Hunters
- NetSupport RMM Tool Abuse
- Storm-0501 Ransomware

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/win_app_defender_disabling/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/disable_windows_behavior_monitoring.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
