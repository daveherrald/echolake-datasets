# Windows Disable Memory Crash Dump

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects attempts to disable the memory crash dump feature on Windows systems by setting the registry value to 0. It leverages data from the Endpoint.Registry datamodel, specifically monitoring changes to the CrashDumpEnabled registry key. This activity is significant because disabling crash dumps can hinder forensic analysis and incident response efforts. If confirmed malicious, this action could be part of a broader attack strategy, such as data destruction or system destabilization, as seen with HermeticWiper, potentially leading to significant operational disruptions and data loss.

## MITRE ATT&CK

- T1485

## Analytic Stories

- Ransomware
- Data Destruction
- Windows Registry Abuse
- Hermetic Wiper

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/hermetic_wiper/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_disable_memory_crash_dump.yml)*
