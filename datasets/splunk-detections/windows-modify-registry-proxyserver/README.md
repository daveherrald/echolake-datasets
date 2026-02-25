# Windows Modify Registry ProxyServer

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting modifications to the Windows registry key for setting up a proxy server. It leverages data from the Endpoint.Registry datamodel, focusing on changes to the "Internet Settings\\ProxyServer" registry path. This activity is significant as it can indicate malware or adversaries configuring a proxy to facilitate unauthorized communication with Command and Control (C2) servers. If confirmed malicious, this could allow attackers to establish persistent, covert channels for data exfiltration or further exploitation of the compromised host.

## MITRE ATT&CK

- T1112

## Analytic Stories

- DarkGate Malware

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/proxy_server/ProxyServer_sys.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_proxyserver.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
