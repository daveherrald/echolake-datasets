# Suspicious Regsvr32 Register Suspicious Path

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the use of Regsvr32.exe to register DLLs from suspicious paths such as AppData, ProgramData, or Windows Temp directories. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs and command-line arguments. This activity is significant because Regsvr32.exe can be abused to proxy execution of malicious code, bypassing traditional security controls. If confirmed malicious, this could allow an attacker to execute arbitrary code, potentially leading to system compromise, data exfiltration, or further lateral movement within the network.

## MITRE ATT&CK

- T1218.010

## Analytic Stories

- Living Off The Land
- Qakbot
- China-Nexus Threat Activity
- Derusbi
- Salt Typhoon
- Suspicious Regsvr32 Activity
- IcedID

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.010/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/suspicious_regsvr32_register_suspicious_path.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
