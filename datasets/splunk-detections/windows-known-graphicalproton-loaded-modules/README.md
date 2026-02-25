# Windows Known GraphicalProton Loaded Modules

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the loading of DLL modules associated with the GraphicalProton backdoor implant, commonly used by SVR in targeted attacks. It leverages Sysmon EventCode 7 to identify specific DLLs loaded by processes. This activity is significant as it may indicate the presence of a sophisticated backdoor, warranting immediate investigation. If confirmed malicious, the attacker could gain persistent access to the compromised host, potentially leading to further exploitation and data exfiltration.

## MITRE ATT&CK

- T1574.001

## Analytic Stories

- Hellcat Ransomware
- CISA AA23-347A
- Water Gamayun

## Data Sources

- Sysmon EventID 7

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1574.002/svr_loaded_modules/loaded_module_svr.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_known_graphicalproton_loaded_modules.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
