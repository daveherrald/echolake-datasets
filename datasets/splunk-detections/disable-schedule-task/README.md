# Disable Schedule Task

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the execution of a command to disable an existing scheduled task using 'schtasks.exe' with the '/change' and '/disable' parameters. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line arguments. Disabling scheduled tasks is significant as it is a common tactic used by adversaries, including malware like IcedID, to disable security applications and evade detection. If confirmed malicious, this activity could allow attackers to persist undetected, disable critical security defenses, and further compromise the targeted host.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- IcedID
- Living Off The Land

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/disable_schtask/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/disable_schedule_task.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
