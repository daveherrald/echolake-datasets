# Disabling Defender Services

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

This dataset contains sample data for detecting the disabling of Windows Defender services by monitoring registry modifications. It leverages registry event data to identify changes to specific registry paths associated with Defender services, where the 'Start' value is set to '0x00000004'. This activity is significant because disabling Defender services can indicate an attempt by an adversary to evade detection and maintain persistence on the endpoint. If confirmed malicious, this action could allow attackers to execute further malicious activities undetected, leading to potential data breaches or system compromise.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- IcedID
- Windows Registry Abuse
- RedLine Stealer

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/disable_av/sysmon2.log


---

*Source: [Splunk Security Content](detections/endpoint/disabling_defender_services.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
