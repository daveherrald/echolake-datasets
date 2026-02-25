# Suspicious Copy on System32

**Type:** Anomaly

**Author:** Teoderick Contreras, Nasreddine Bencherchali, Splunk

## Description

This dataset contains sample data for detecting potentially suspicious file copy operations targeting the
System32 or SysWow64 directories as source, often indicative of malicious activity.
It leverages data from Endpoint Detection and Response (EDR) agents, 
focusing on activity initiated by command-line tools like cmd.exe or PowerShell.
This behavior is significant as it may indicate an attempt to evade defenses by copying
an existing binary from the system directory and renaming it.
If confirmed malicious, this activity could allow an attacker to execute
code undetected and potentially leading to system compromise or further lateral movement
within the network.


## MITRE ATT&CK

- T1036.003

## Analytic Stories

- Qakbot
- Sandworm Tools
- IcedID
- Volt Typhoon
- AsyncRAT
- Unusual Processes
- Compromised Windows Host
- Water Gamayun

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036.003/copy_sysmon/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/suspicious_copy_on_system32.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
