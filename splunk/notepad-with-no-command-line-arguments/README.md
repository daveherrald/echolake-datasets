# Notepad with no Command Line Arguments

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies instances where Notepad.exe is launched without any command line arguments, a behavior commonly associated with the SliverC2 framework. This detection leverages process creation events from Endpoint Detection and Response (EDR) agents, focusing on processes initiated by Notepad.exe within a short time frame. This activity is significant as it may indicate an attempt to inject malicious code into Notepad.exe, a known tactic for evading detection. If confirmed malicious, this could allow an attacker to execute arbitrary code, potentially leading to system compromise and unauthorized access.

## MITRE ATT&CK

- T1055

## Analytic Stories

- BishopFox Sliver Adversary Emulation Framework

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/sliver/notepad_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/notepad_with_no_command_line_arguments.yml)*
