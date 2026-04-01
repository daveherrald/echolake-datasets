# Mmc LOLBAS Execution Process Spawn

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying `mmc.exe` spawning a LOLBAS execution process. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process creation events where `mmc.exe` is the parent process. This activity is significant because adversaries can abuse the DCOM protocol and MMC20 COM object to execute malicious code, using Windows native binaries documented by the LOLBAS project. If confirmed malicious, this behavior could indicate lateral movement, allowing attackers to execute code remotely, potentially leading to further compromise and persistence within the environment.

## MITRE ATT&CK

- T1021.003
- T1218.014

## Analytic Stories

- Active Directory Lateral Movement
- Living Off The Land
- Water Gamayun

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.003/lateral_movement_lolbas/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/mmc_lolbas_execution_process_spawn.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
