# Windows Modify Registry USeWuServer

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting a suspicious modification to the Windows Update configuration registry key "UseWUServer." It leverages data from the Endpoint.Registry data model to identify changes where the registry value is set to "0x00000001." This activity is significant because it is commonly used by adversaries, including malware like RedLine Stealer, to bypass detection mechanisms and potentially exploit zero-day vulnerabilities. If confirmed malicious, this modification could allow attackers to evade defenses, persist on the target host, and deploy additional malicious payloads.

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

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_usewuserver.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
