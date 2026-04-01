# Windows Modify Registry No Auto Reboot With Logon User

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting a suspicious modification to the Windows registry that disables automatic reboot with a logged-on user. This detection leverages the Endpoint data model to identify changes to the registry path `SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoRebootWithLoggedOnUsers` with a value of `0x00000001`. This activity is significant as it is commonly used by adversaries, including malware like RedLine Stealer, to evade detection and maintain persistence. If confirmed malicious, this could allow attackers to bypass security measures and deploy additional payloads without interruption.

## MITRE ATT&CK

- T1112

## Analytic Stories

- RedLine Stealer

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/redline/modify_registry/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_no_auto_reboot_with_logon_user.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
