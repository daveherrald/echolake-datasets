# Windows IIS Components Add New Module

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the execution of AppCmd.exe to install a new module in IIS. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant as adversaries may use it to install webshells or backdoors, leading to credit card scraping, persistence, and further post-exploitation. If confirmed malicious, this could allow attackers to maintain persistent access, execute arbitrary code, and potentially exfiltrate sensitive information from the compromised web server.

## MITRE ATT&CK

- T1505.004

## Analytic Stories

- IIS Components
- GhostRedirector IIS Module and Rungan Backdoor

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1505.004/appcmd_install-windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_iis_components_add_new_module.yml)*
