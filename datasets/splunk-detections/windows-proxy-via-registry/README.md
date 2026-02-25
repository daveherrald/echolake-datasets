# Windows Proxy Via Registry

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the modification of registry keys related to the Windows Proxy settings via netsh.exe. It leverages data from the Endpoint.Registry data model, focusing on changes to the registry path "*\\System\\CurrentControlSet\\Services\\PortProxy\\v4tov4\\tcp*". This activity is significant because netsh.exe can be used to establish a persistent proxy, potentially allowing an attacker to execute a helper DLL whenever netsh.exe runs. If confirmed malicious, this could enable the attacker to maintain persistence, manipulate network configurations, and potentially exfiltrate data or further compromise the system.

## MITRE ATT&CK

- T1090.001

## Analytic Stories

- Volt Typhoon

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1090.001/netsh_portproxy/volt_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_proxy_via_registry.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
