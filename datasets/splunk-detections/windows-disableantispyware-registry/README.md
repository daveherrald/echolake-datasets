# Windows DisableAntiSpyware Registry

**Type:** TTP

**Author:** Rod Soto, Jose Hernandez, Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the modification of the Windows Registry key "DisableAntiSpyware" being set to disable. This detection leverages data from the Endpoint.Registry datamodel, specifically looking for the registry value name "DisableAntiSpyware" with a value of "0x00000001". This activity is significant as it is commonly associated with Ryuk ransomware infections, indicating potential malicious intent to disable Windows Defender. If confirmed malicious, this action could allow attackers to disable critical security defenses, facilitating further malicious activities such as data encryption, exfiltration, or additional system compromise.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Azorult
- Ryuk Ransomware
- Windows Registry Abuse
- RedLine Stealer
- CISA AA22-264A
- Windows Defense Evasion Tactics
- CISA AA23-347A

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_disableantispyware_registry.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
