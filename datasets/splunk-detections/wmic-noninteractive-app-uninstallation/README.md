# Wmic NonInteractive App Uninstallation

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying the use of the WMIC command-line tool attempting to uninstall applications non-interactively. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on specific command-line patterns associated with WMIC. This activity is significant because it is uncommon and may indicate an attempt to evade detection by uninstalling security software, as seen in IcedID malware campaigns. If confirmed malicious, this behavior could allow an attacker to disable security defenses, facilitating further compromise and persistence within the environment.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- IcedID
- Azorult

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/disable_av/sysmon2.log


---

*Source: [Splunk Security Content](detections/endpoint/wmic_noninteractive_app_uninstallation.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
