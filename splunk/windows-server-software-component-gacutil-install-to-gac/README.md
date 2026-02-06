# Windows Server Software Component GACUtil Install to GAC

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the use of GACUtil.exe to add a DLL into the Global Assembly Cache (GAC). It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant because adding a DLL to the GAC allows it to be called by any application, potentially enabling widespread code execution. If confirmed malicious, this could allow an attacker to execute arbitrary code across the operating system, leading to privilege escalation or persistent access.

## MITRE ATT&CK

- T1505.004

## Analytic Stories

- IIS Components

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1505.004/gacutil_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_server_software_component_gacutil_install_to_gac.yml)*
