# Windows Impair Defense Deny Security Software With Applocker

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting modifications in the Windows registry by the Applocker utility that deny the execution of various security products. This detection leverages data from the Endpoint.Registry datamodel, focusing on specific registry paths and values indicating a "Deny" action against known antivirus and security software. This activity is significant as it may indicate an attempt to disable security defenses, a tactic observed in malware like Azorult. If confirmed malicious, this could allow attackers to bypass security measures, facilitating further malicious activities and persistence within the environment.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Azorult
- Scattered Lapsus$ Hunters

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/azorult/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_impair_defense_deny_security_software_with_applocker.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
