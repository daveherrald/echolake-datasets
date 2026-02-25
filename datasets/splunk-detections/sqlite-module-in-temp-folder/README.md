# Sqlite Module In Temp Folder

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the creation of sqlite3.dll files in the %temp% folder. It leverages Sysmon EventCode 11 to identify when these files are written to the temporary directory. This activity is significant because it is associated with IcedID malware, which uses the sqlite3 module to parse browser databases and steal sensitive information such as banking details, credit card information, and credentials. If confirmed malicious, this behavior could lead to significant data theft and compromise of user accounts.

## MITRE ATT&CK

- T1005

## Analytic Stories

- IcedID
- Lokibot

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/simulated_icedid/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/sqlite_module_in_temp_folder.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
