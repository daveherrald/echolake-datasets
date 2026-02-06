# Detect Exchange Web Shell

**Type:** TTP

**Author:** Michael Haag, Shannon Davis, David Dorsey, Splunk

## Description

The following analytic identifies the creation of suspicious .aspx files in known drop locations for Exchange exploitation, specifically targeting paths associated with HAFNIUM group and vulnerabilities like ProxyShell and ProxyNotShell. It leverages data from the Endpoint datamodel, focusing on process and filesystem events. This activity is significant as it may indicate a web shell deployment, a common method for persistent access and remote code execution. If confirmed malicious, attackers could gain unauthorized access, execute arbitrary commands, and potentially escalate privileges within the Exchange environment.

## MITRE ATT&CK

- T1133
- T1190
- T1505.003

## Analytic Stories

- ProxyNotShell
- CISA AA22-257A
- HAFNIUM Group
- ProxyShell
- Compromised Windows Host
- BlackByte Ransomware
- Seashell Blizzard
- GhostRedirector IIS Module and Rungan Backdoor

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1505.003/windows-sysmon_proxylogon.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_exchange_web_shell.yml)*
