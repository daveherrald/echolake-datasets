# Windows Wmic CPU Discovery

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the use of WMIC (Windows Management Instrumentation Command-line) for CPU discovery, often executed with commands such as “wmic cpu get name” This behavior is commonly associated with reconnaissance, where adversaries seek to gather details about system hardware, assess processing power, or determine if the environment is virtualized. While WMIC is a legitimate administrative tool, its use for CPU queries outside of normal inventory or management scripts can indicate malicious intent. Monitoring command-line executions of WMIC with CPU-related arguments and correlating with other discovery activity can help identify attacker reconnaissance.

## MITRE ATT&CK

- T1082

## Analytic Stories

- LAMEHUG

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/lamehug/T1082/wmic_cmd/wmic_cmd.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_wmic_cpu_discovery.yml)*
