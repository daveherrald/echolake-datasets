# Suspicious Process Executed From Container File

**Type:** TTP

**Author:** Steven Dick

## Description

The following analytic identifies a suspicious process executed from within common container/archive file types such as ZIP, ISO, IMG, and others. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant as it is a common technique used by adversaries to execute scripts or evade defenses. If confirmed malicious, this behavior could allow attackers to execute arbitrary code, escalate privileges, or persist within the environment, posing a significant security risk.

## MITRE ATT&CK

- T1204.002
- T1036.008

## Analytic Stories

- APT37 Rustonotto and FadeStealer
- GhostRedirector IIS Module and Rungan Backdoor
- Unusual Processes
- Amadey
- Remcos
- Snake Keylogger
- Water Gamayun

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/gootloader/partial_ttps/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/suspicious_process_executed_from_container_file.yml)*
