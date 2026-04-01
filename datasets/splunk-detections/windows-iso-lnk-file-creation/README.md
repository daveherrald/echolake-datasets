# Windows ISO LNK File Creation

**Type:** Hunting

**Author:** Michael Haag, Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the creation of .iso.lnk files in the %USER%\AppData\Local\Temp\<random folder name>\ path, indicating that an ISO file has been mounted and accessed. This detection leverages the Endpoint.Filesystem data model, specifically monitoring file creation events in the Windows Recent folder. This activity is significant as it may indicate the delivery and execution of potentially malicious payloads via ISO files. If confirmed malicious, this could lead to unauthorized code execution, data exfiltration, or further system compromise.

## MITRE ATT&CK

- T1204.001
- T1566.001

## Analytic Stories

- Spearphishing Attachments
- Brute Ratel C4
- AgentTesla
- Qakbot
- IcedID
- Azorult
- Remcos
- Warzone RAT
- Amadey
- Gozi Malware
- APT37 Rustonotto and FadeStealer

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1556.001/atomic_red_team/iso_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_iso_lnk_file_creation.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
