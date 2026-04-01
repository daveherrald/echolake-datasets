# Windows Impair Defense Disable Defender Protocol Recognition

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting modifications to the Windows registry that disable the Windows Defender protocol recognition feature. It leverages data from the Endpoint.Registry data model, specifically looking for changes to the "DisableProtocolRecognition" setting. This activity is significant because disabling protocol recognition can hinder Windows Defender's ability to detect and respond to malware or suspicious software. If confirmed malicious, this action could allow an attacker to bypass antivirus defenses, facilitating further malicious activities such as data exfiltration or system compromise.

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

*Source: [Splunk Security Content](detections/endpoint/windows_impair_defense_disable_defender_protocol_recognition.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
