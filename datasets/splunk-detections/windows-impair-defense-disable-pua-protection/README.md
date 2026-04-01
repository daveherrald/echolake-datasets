# Windows Impair Defense Disable PUA Protection

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting a modification in the Windows registry to disable Windows Defender PUA protection by setting PUAProtection to 0. This detection leverages data from the Endpoint.Registry datamodel, focusing on registry path changes related to Windows Defender. Disabling PUA protection is significant as it reduces defenses against Potentially Unwanted Applications (PUAs), which, while not always malicious, can negatively impact user experience and security. If confirmed malicious, this activity could allow an attacker to introduce adware, browser toolbars, or other unwanted software, potentially compromising system integrity and user productivity.

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

*Source: [Splunk Security Content](detections/endpoint/windows_impair_defense_disable_pua_protection.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
