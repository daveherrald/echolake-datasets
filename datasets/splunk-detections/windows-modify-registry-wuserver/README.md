# Windows Modify Registry WuServer

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting suspicious modifications to the Windows Update Server (WUServer) registry settings. It leverages data from the Endpoint.Registry data model to identify changes in the registry path associated with Windows Update configurations. This activity is significant because adversaries, including malware like RedLine Stealer, exploit this technique to bypass detection and deploy additional payloads. If confirmed malicious, this registry modification could allow attackers to evade defenses, potentially leading to further system compromise and persistent unauthorized access.

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

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_wuserver.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
