# Detect AzureHound File Modifications

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the creation of specific AzureHound-related files, such as `*-azurecollection.zip` and various `.json` files, on disk. It leverages data from the Endpoint.Filesystem datamodel, focusing on file creation events with specific filenames. This activity is significant because AzureHound is a tool used to gather information about Azure environments, similar to SharpHound for on-premises Active Directory. If confirmed malicious, this activity could indicate an attacker is collecting sensitive Azure environment data, potentially leading to further exploitation or privilege escalation within the cloud infrastructure.

## MITRE ATT&CK

- T1069.001
- T1069.002
- T1087.001
- T1087.002
- T1482

## Analytic Stories

- Windows Discovery Techniques

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/sharphound/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_azurehound_file_modifications.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
