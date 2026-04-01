# Cisco NVM - Susp Script From Archive Triggering Network Activity

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This analytic detects script execution (`wscript.exe` or `cscript.exe`) triggered from compressed files opened directly using
`explorer.exe`, `winrar.exe`, or `7zFM.exe`.
When a user double clicks on a ".js" file from within one of these compressed files. Its extracted temporally in the temp directory in folder with certain markers.
It leverages Cisco Network Visibility Module (NVM) flow data, in order to look for a specific parent/child relationship and an initiated network connection.
This behavior is exploited by threat actors such as Scarlet Goldfinch to deliver and run malicious scripts as an initial access technique.


## MITRE ATT&CK

- T1059.005
- T1204.002

## Analytic Stories

- Cisco Network Visibility Module Analytics

## Data Sources

- Cisco Network Visibility Module Flow Data

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:nvm:flowdata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_network_visibility_module/cisco_nvm_flowdata/nvm_flowdata.log


---

*Source: [Splunk Security Content](detections/endpoint/cisco_nvm___susp_script_from_archive_triggering_network_activity.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
