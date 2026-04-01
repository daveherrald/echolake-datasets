# Cisco NVM - Rclone Execution With Network Activity

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This detection identifies execution of the file synchronization utility "rclone".
It leverages Cisco Network Visibility Module logs, specifically flow data in order to capture process executions
initiating network connections.
While rclone is a legitimate command-line tool for syncing data to cloud storage providers, it has been widely abused by threat actors for data exfiltration.
This analytic inspects process name and arguments for rclone and flags usage of suspicious flags.
If matched, this could indicate malicious usage for stealthy data exfiltration or cloud abuse.


## MITRE ATT&CK

- T1567.002

## Analytic Stories

- Scattered Lapsus$ Hunters
- Cisco Network Visibility Module Analytics

## Data Sources

- Cisco Network Visibility Module Flow Data

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:nvm:flowdata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_network_visibility_module/cisco_nvm_flowdata/nvm_flowdata.log


---

*Source: [Splunk Security Content](detections/endpoint/cisco_nvm___rclone_execution_with_network_activity.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
