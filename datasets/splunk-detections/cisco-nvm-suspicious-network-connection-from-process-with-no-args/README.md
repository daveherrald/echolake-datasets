# Cisco NVM - Suspicious Network Connection From Process With No Args

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This analytic detects system binaries that are commonly abused in process injection techniques but are observed without any command-line arguments.
It leverages Cisco Network Visibility Module (NVM) flow data and process arguments
to identify outbound connections initiated by curl where TLS checks were explicitly disabled.
Binaries such as `rundll32.exe`, `regsvr32.exe`, `dllhost.exe`, `svchost.exe`, and others are legitimate Windows processes that are often injected into by malware or post-exploitation frameworks (e.g., Cobalt Strike) to hide execution.
When these processes are seen initiating a network connection with an empty or missing command line, it can indicate
potential injection and communication with a command and control server.


## MITRE ATT&CK

- T1055
- T1218

## Analytic Stories

- Cisco Network Visibility Module Analytics

## Data Sources

- Cisco Network Visibility Module Flow Data

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:nvm:flowdata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_network_visibility_module/cisco_nvm_flowdata/nvm_flowdata.log


---

*Source: [Splunk Security Content](detections/endpoint/cisco_nvm___suspicious_network_connection_from_process_with_no_args.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
