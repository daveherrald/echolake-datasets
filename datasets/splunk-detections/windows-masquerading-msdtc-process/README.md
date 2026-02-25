# Windows Masquerading Msdtc Process

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying the execution of msdtc.exe with specific command-line parameters (-a or -b), which are indicative of the PlugX malware. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line arguments. This activity is significant because PlugX uses these parameters to masquerade its malicious operations within legitimate processes, making it harder to detect. If confirmed malicious, this behavior could allow attackers to gain unauthorized access, exfiltrate data, and conduct espionage, severely compromising the affected system.

## MITRE ATT&CK

- T1036

## Analytic Stories

- Compromised Windows Host
- PlugX

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036/msdtc_process_param/msdtc_a_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_masquerading_msdtc_process.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
