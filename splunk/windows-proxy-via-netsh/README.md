# Windows Proxy Via Netsh

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies the use of netsh.exe to configure a connection proxy, which can be leveraged for persistence by executing a helper DLL. It detects this activity by analyzing process creation events from Endpoint Detection and Response (EDR) agents, focusing on command-line executions involving "portproxy" and "v4tov4" parameters. This activity is significant because it indicates potential unauthorized network configuration changes, which could be used to maintain persistence or redirect network traffic. If confirmed malicious, this could allow an attacker to maintain covert access or manipulate network communications, posing a significant security risk.

## MITRE ATT&CK

- T1090.001

## Analytic Stories

- Volt Typhoon

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1090.001/netsh_portproxy/volt_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_proxy_via_netsh.yml)*
