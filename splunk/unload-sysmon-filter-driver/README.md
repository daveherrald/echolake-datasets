# Unload Sysmon Filter Driver

**Type:** TTP

**Author:** Bhavin Patel, Splunk

## Description

The following analytic detects the use of `fltMC.exe` to unload the Sysmon driver, which stops Sysmon from collecting data. It leverages Endpoint Detection and Response (EDR) logs, focusing on process names and command-line executions. This activity is significant because disabling Sysmon can blind security monitoring, allowing malicious actions to go undetected. If confirmed malicious, this could enable attackers to execute further attacks without being logged, leading to potential data breaches, privilege escalation, or persistent access within the environment.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- CISA AA23-347A
- Disabling Security Tools

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/unload_sysmon/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/unload_sysmon_filter_driver.yml)*
