# Windows Impair Defense Disable Win Defender Compute File Hashes

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting modifications to the Windows registry that disable Windows Defender's file hash computation by setting the EnableFileHashComputation value to 0. This detection leverages data from the Endpoint.Registry data model, focusing on changes to the specific registry path associated with Windows Defender. Disabling file hash computation can significantly impair Windows Defender's ability to detect and scan for malware, making it a critical behavior to monitor. If confirmed malicious, this activity could allow attackers to bypass Windows Defender, facilitating undetected malware execution and persistence in the environment.

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

*Source: [Splunk Security Content](detections/endpoint/windows_impair_defense_disable_win_defender_compute_file_hashes.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
