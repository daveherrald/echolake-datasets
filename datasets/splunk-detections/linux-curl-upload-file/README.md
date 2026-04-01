# Linux Curl Upload File

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the use of the curl command with specific switches (-F, --form, --upload-file, -T, -d, --data, --data-raw, -I, --head) to upload AWS credentials or configuration files to a remote destination. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions and process details. This activity is significant as it may indicate an attempt to exfiltrate sensitive AWS credentials, a technique known to be used by the TeamTNT group. If confirmed malicious, this could lead to unauthorized access and potential compromise of AWS resources.

## MITRE ATT&CK

- T1105

## Analytic Stories

- Linux Living Off The Land
- Data Exfiltration
- Ingress Tool Transfer
- NPM Supply Chain Compromise

## Data Sources

- Sysmon for Linux EventID 1
- Cisco Isovalent Process Exec

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1105/atomic_red_team/curl-linux-sysmon.log

- **Source:** not_applicable
  **Sourcetype:** cisco:isovalent:processExec
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_isovalent/cisco_isovalent.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_curl_upload_file.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
