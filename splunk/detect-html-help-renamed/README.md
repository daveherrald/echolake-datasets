# Detect HTML Help Renamed

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

The following analytic detects instances where hh.exe (HTML Help) has been renamed and is executing a Compiled HTML Help (CHM) file. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and original file names. This activity is significant because attackers can use renamed hh.exe to execute malicious scripts embedded in CHM files, potentially leading to code execution. If confirmed malicious, this technique could allow attackers to run arbitrary scripts, escalate privileges, or persist within the environment, posing a significant security risk.

## MITRE ATT&CK

- T1218.001

## Analytic Stories

- Suspicious Compiled HTML Activity
- Living Off The Land
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

*Source: [Splunk Security Content](detections/endpoint/detect_html_help_renamed.yml)*
