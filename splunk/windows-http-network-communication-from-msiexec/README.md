# Windows HTTP Network Communication From MSIExec

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

The following analytic detects MSIExec making network connections over ports 443 or 80. This behavior is identified by correlating process creation events from Endpoint Detection and Response (EDR) agents with network traffic logs. Typically, MSIExec does not perform network communication to the internet, making this activity unusual and potentially indicative of malicious behavior. If confirmed malicious, an attacker could be using MSIExec to download or communicate with external servers, potentially leading to data exfiltration, command and control (C2) communication, or further malware deployment.

## MITRE ATT&CK

- T1218.007

## Analytic Stories

- APT37 Rustonotto and FadeStealer
- GhostRedirector IIS Module and Rungan Backdoor
- Windows System Binary Proxy Execution MSIExec
- Water Gamayun
- Cisco Network Visibility Module Analytics

## Data Sources

- Sysmon EventID 1 AND Sysmon EventID 3
- Cisco Network Visibility Module Flow Data

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.007/atomic_red_team/windows-sysmon.log

- **Source:** not_applicable
  **Sourcetype:** cisco:nvm:flowdata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_network_visibility_module/cisco_nvm_flowdata/nvm_flowdata.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_http_network_communication_from_msiexec.yml)*
