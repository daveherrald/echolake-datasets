# Windows Impair Defense Overide Win Defender Phishing Filter

**Type:** TTP

**Author:** Teoderick Contreras, Bhavin Patel, Splunk

## Description

This dataset contains sample data for detecting modifications to the Windows registry that disable the Windows Defender phishing filter. It leverages data from the Endpoint.Registry data model, focusing on changes to specific registry values related to Microsoft Edge's phishing filter settings. This activity is significant because disabling the phishing filter can allow attackers to deceive users into visiting malicious websites without triggering browser warnings. If confirmed malicious, this could lead to users unknowingly accessing harmful sites, resulting in potential security incidents or data compromises.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Windows Defense Evasion Tactics
- Windows Registry Abuse

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/disable-windows-security-defender-features/windefender-bypas-2-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_impair_defense_overide_win_defender_phishing_filter.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
