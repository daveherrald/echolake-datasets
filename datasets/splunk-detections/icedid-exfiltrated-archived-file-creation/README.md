# IcedID Exfiltrated Archived File Creation

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the creation of suspicious files named passff.tar and cookie.tar, which are indicative of archived stolen browser information such as history and cookies on a machine compromised with IcedID. It leverages Sysmon EventCode 11 to identify these specific filenames. This activity is significant because it suggests that sensitive browser data has been exfiltrated, which could lead to further exploitation or data breaches. If confirmed malicious, this could allow attackers to access personal information, conduct further phishing attacks, or escalate their presence within the network.

## MITRE ATT&CK

- T1560.001

## Analytic Stories

- IcedID
- APT37 Rustonotto and FadeStealer

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/simulated_icedid/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/icedid_exfiltrated_archived_file_creation.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
