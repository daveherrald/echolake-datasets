# Process Creating LNK file in Suspicious Location

**Type:** TTP

**Author:** Jose Hernandez, Michael Haag, Splunk

## Description

This dataset contains sample data for detecting a process creating a `.lnk` file in suspicious locations such as `C:\User*` or `*\Local\Temp\*`. It leverages filesystem and process activity data from the Endpoint data model to identify this behavior. This activity is significant because creating `.lnk` files in these directories is a common tactic used by spear phishing tools to establish persistence or execute malicious payloads. If confirmed malicious, this could allow an attacker to maintain persistence, execute arbitrary code, or further compromise the system.

## MITRE ATT&CK

- T1566.002

## Analytic Stories

- Spearphishing Attachments
- Qakbot
- IcedID
- Amadey
- Gozi Malware
- APT37 Rustonotto and FadeStealer

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.002/lnk_file_temp_folder/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/process_creating_lnk_file_in_suspicious_location.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
