# Windows Process Execution From ProgramData

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies processes running from file paths within the ProgramData directory, a common location abused by adversaries for executing malicious code while evading detection. Threat actors often drop and execute payloads from this directory to bypass security controls, as it typically has write permissions for standard users. While this behavior can indicate malware execution or persistence techniques, it is important to note that some legitimate software, installers, and update mechanisms also run from ProgramData, leading to potential false positives. Security teams should validate detections by correlating with other indicators, such as unusual parent processes, unsigned binaries, or anomalous network activity.

## MITRE ATT&CK

- T1036.005

## Analytic Stories

- StealC Stealer
- SnappyBee
- XWorm
- Salt Typhoon
- China-Nexus Threat Activity
- APT37 Rustonotto and FadeStealer
- GhostRedirector IIS Module and Rungan Backdoor

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036.005/process_in_programdata/exec_programdata.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_process_execution_from_programdata.yml)*
