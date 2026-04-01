# Disable Defender AntiVirus Registry

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

This dataset contains sample data for detecting the modification of Windows Defender registry settings to disable antivirus and antispyware protections. It leverages data from the Endpoint.Registry data model, specifically monitoring changes to registry paths associated with Windows Defender policies. This activity is significant because disabling antivirus protections is a common tactic used by adversaries to evade detection and maintain persistence on compromised systems. If confirmed malicious, this action could allow attackers to execute further malicious activities undetected, leading to potential data breaches, system compromise, and further propagation of malware within the network.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Windows Registry Abuse
- CISA AA24-241A
- IcedID
- Black Basta Ransomware
- Cactus Ransomware

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/disable_av/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/disable_defender_antivirus_registry.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
