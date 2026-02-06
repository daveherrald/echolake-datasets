# Spoolsv Spawning Rundll32

**Type:** TTP

**Author:** Mauricio Velazco, Michael Haag, Splunk

## Description

The following analytic detects the spawning of `rundll32.exe` without command-line arguments by `spoolsv.exe`, which is unusual and potentially indicative of exploitation attempts like CVE-2021-34527 (PrintNightmare). This detection leverages Endpoint Detection and Response (EDR) telemetry, focusing on process creation events where `spoolsv.exe` is the parent process. This activity is significant as `spoolsv.exe` typically does not spawn other processes, and such behavior could indicate an active exploitation attempt. If confirmed malicious, this could allow an attacker to execute arbitrary code, escalate privileges, or maintain persistence on the compromised endpoint.

## MITRE ATT&CK

- T1547.012

## Analytic Stories

- PrintNightmare CVE-2021-34527
- Compromised Windows Host
- Black Basta Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.012/printnightmare/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/spoolsv_spawning_rundll32.yml)*
