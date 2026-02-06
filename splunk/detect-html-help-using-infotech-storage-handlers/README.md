# Detect HTML Help Using InfoTech Storage Handlers

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the execution of hh.exe (HTML Help) using InfoTech Storage Handlers to load Windows script code from a Compiled HTML Help (CHM) file. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant because it can be used to execute malicious scripts embedded within CHM files, potentially leading to code execution. If confirmed malicious, this technique could allow an attacker to execute arbitrary code, escalate privileges, or persist within the environment.

## MITRE ATT&CK

- T1218.001

## Analytic Stories

- Suspicious Compiled HTML Activity
- Living Off The Land
- Compromised Windows Host
- APT37 Rustonotto and FadeStealer

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.001/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_html_help_using_infotech_storage_handlers.yml)*
