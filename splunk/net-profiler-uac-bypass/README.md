# NET Profiler UAC bypass

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects modifications to the registry aimed at bypassing the User Account Control (UAC) feature in Windows. It identifies changes to the .NET COR_PROFILER_PATH registry key, which can be exploited to load a malicious DLL via mmc.exe. This detection leverages data from the Endpoint.Registry datamodel, focusing on specific registry paths and values. Monitoring this activity is crucial as it can indicate an attempt to escalate privileges or persist within the environment. If confirmed malicious, this could allow an attacker to execute arbitrary code with elevated privileges, compromising system integrity.

## MITRE ATT&CK

- T1548.002

## Analytic Stories

- Windows Defense Evasion Tactics

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/uac_bypass/windows-sysmon2.log


---

*Source: [Splunk Security Content](detections/endpoint/net_profiler_uac_bypass.yml)*
