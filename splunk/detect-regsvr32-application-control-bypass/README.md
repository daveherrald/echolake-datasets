# Detect Regsvr32 Application Control Bypass

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies the abuse of Regsvr32.exe to proxy execution of malicious code, specifically detecting the loading of "scrobj.dll" by Regsvr32.exe. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process creation events and command-line executions. This activity is significant because Regsvr32.exe is a trusted, signed Microsoft binary, often used in "Squiblydoo" attacks to bypass application control mechanisms. If confirmed malicious, this technique could allow an attacker to execute arbitrary code, potentially leading to system compromise and persistent access.

## MITRE ATT&CK

- T1218.010

## Analytic Stories

- Living Off The Land
- Suspicious Regsvr32 Activity
- Graceful Wipe Out Attack
- Cobalt Strike
- Compromised Windows Host
- BlackByte Ransomware
- PHP-CGI RCE Attack on Japanese Organizations

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.010/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_regsvr32_application_control_bypass.yml)*
