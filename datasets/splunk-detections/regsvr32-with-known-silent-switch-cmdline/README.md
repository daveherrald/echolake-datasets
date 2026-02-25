# Regsvr32 with Known Silent Switch Cmdline

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the execution of Regsvr32.exe with the silent switch to load DLLs. This behavior is identified using Endpoint Detection and Response (EDR) telemetry, focusing on command-line executions containing the `-s` or `/s` switches. This activity is significant as it is commonly used in malware campaigns, such as IcedID, to stealthily load malicious DLLs. If confirmed malicious, this could allow an attacker to execute arbitrary code, download additional payloads, and potentially compromise the system further. Immediate investigation and endpoint isolation are recommended.

## MITRE ATT&CK

- T1218.010

## Analytic Stories

- IcedID
- Suspicious Regsvr32 Activity
- Remcos
- Living Off The Land
- Qakbot
- AsyncRAT

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/inf_icedid/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/regsvr32_with_known_silent_switch_cmdline.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
