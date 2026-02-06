# Remote WMI Command Attempt

**Type:** TTP

**Author:** Rico Valdez, Michael Haag, Splunk

## Description

The following analytic detects the execution of `wmic.exe` with the `node` switch, indicating an attempt to spawn a local or remote process. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process creation events and command-line arguments. This activity is significant as it may indicate lateral movement or remote code execution attempts by an attacker. If confirmed malicious, the attacker could gain remote control over the targeted system, execute arbitrary commands, and potentially escalate privileges or persist within the environment.

## MITRE ATT&CK

- T1047

## Analytic Stories

- Graceful Wipe Out Attack
- Volt Typhoon
- Living Off The Land
- IcedID
- Suspicious WMI Use
- CISA AA23-347A

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1047/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/remote_wmi_command_attempt.yml)*
