# Windows Modify Registry Tamper Protection

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting a suspicious modification to the Windows Defender Tamper Protection registry setting. It leverages data from the Endpoint datamodel, specifically targeting changes where the registry path is set to disable Tamper Protection. This activity is significant because disabling Tamper Protection can allow adversaries to make further undetected changes to Windows Defender settings, potentially leading to reduced security on the system. If confirmed malicious, this could enable attackers to evade detection, persist in the environment, and execute further malicious activities without interference from Windows Defender.

## MITRE ATT&CK

- T1112

## Analytic Stories

- Scattered Lapsus$ Hunters
- RedLine Stealer

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/redline/modify_registry/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_tamper_protection.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
