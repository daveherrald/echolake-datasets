# Cisco NVM - Non-Network Binary Making Network Connection

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This analytic detects network connections initiated by binaries that are not typically associated with network communication,
such as 'notepad.exe', 'calc.exe' or 'write.exe'.
It leverages Cisco Network Visibility Module logs to correlate network flow activity with process context, including command-line arguments, process path, and parent process information.
These applications are normally used for locally and do not require outbound network access. When they do initiate such connections, it may indicate process hollowing, code injection, or proxy execution, where adversaries abuse a trusted process to mask malicious activity.


## MITRE ATT&CK

- T1055
- T1036

## Analytic Stories

- Cisco Network Visibility Module Analytics

## Data Sources

- Cisco Network Visibility Module Flow Data

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:nvm:flowdata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_network_visibility_module/cisco_nvm_flowdata/nvm_flowdata.log


---

*Source: [Splunk Security Content](detections/endpoint/cisco_nvm___non_network_binary_making_network_connection.yml)*
