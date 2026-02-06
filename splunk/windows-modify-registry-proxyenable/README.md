# Windows Modify Registry ProxyEnable

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects modifications to the Windows registry key "ProxyEnable" to enable proxy settings. It leverages data from the Endpoint.Registry datamodel, specifically monitoring changes to the "Internet Settings\ProxyEnable" registry path. This activity is significant as it is commonly exploited by malware and adversaries to establish proxy communication, potentially connecting to malicious Command and Control (C2) servers. If confirmed malicious, this could allow attackers to redirect network traffic through a proxy, facilitating unauthorized communication and data exfiltration, thereby compromising the security of the affected host.

## MITRE ATT&CK

- T1112

## Analytic Stories

- DarkGate Malware

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/proxy_enable/proxyenable.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_proxyenable.yml)*
