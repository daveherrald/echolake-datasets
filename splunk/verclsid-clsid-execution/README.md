# Verclsid CLSID Execution

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the potential abuse of the verclsid.exe utility to execute malicious files via generated CLSIDs. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on specific command-line patterns associated with verclsid.exe. This activity is significant because verclsid.exe is a legitimate Windows application used to verify CLSID COM objects, and its misuse can indicate an attempt to bypass security controls. If confirmed malicious, this technique could allow an attacker to execute arbitrary code, potentially leading to system compromise or further malicious activities.

## MITRE ATT&CK

- T1218.012

## Analytic Stories

- Unusual Processes

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.012/verclsid_exec/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/verclsid_clsid_execution.yml)*
