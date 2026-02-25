# Windows Modify Registry ValleyRAT C2 Config

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting modifications to theregistry related to ValleyRAT C2 configuration. Specifically,  it monitors changes in registry keys where ValleyRAT saves the IP address and port information of its command-and-control (C2) server. This activity is a key indicator of ValleyRAT attempting to establish persistent communication with its C2 infrastructure. By identifying these unauthorized registry modifications, security analysts can quickly detect malicious configurations and investigate the associated threats. Early detection of these changes helps prevent further exploitation and limits the malware’s ability to exfiltrate data or control infected systems.

## MITRE ATT&CK

- T1112

## Analytic Stories

- ValleyRAT

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/valleyrat_c2_reg2/valleyrat_c2_reg2.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_valleyrat_c2_config.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
