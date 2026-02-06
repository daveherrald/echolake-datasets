# CMD Echo Pipe - Escalation

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies the use of named-pipe impersonation for privilege escalation, commonly associated with Cobalt Strike and similar frameworks. It detects command-line executions where `cmd.exe` uses `echo` to write to a named pipe, such as `cmd.exe /c echo 4sgryt3436 > \\.\Pipe\5erg53`. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process and command-line telemetry. This activity is significant as it indicates potential privilege escalation attempts. If confirmed malicious, attackers could gain elevated privileges, enabling further compromise and persistence within the environment.

## MITRE ATT&CK

- T1059.003
- T1543.003

## Analytic Stories

- Graceful Wipe Out Attack
- Cobalt Strike
- Compromised Windows Host
- BlackByte Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/cobalt_strike/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/cmd_echo_pipe___escalation.yml)*
