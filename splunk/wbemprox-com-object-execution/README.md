# Wbemprox COM Object Execution

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects a suspicious process loading a COM object from wbemprox.dll, fastprox.dll, or wbemcomn.dll. It leverages Sysmon EventCode 7 to identify instances where these DLLs are loaded by processes not typically associated with them, excluding known legitimate processes and directories. This activity is significant as it may indicate an attempt by threat actors to abuse COM objects for privilege escalation or evasion of detection mechanisms. If confirmed malicious, this could allow attackers to gain elevated privileges or maintain persistence within the environment, posing a significant security risk.

## MITRE ATT&CK

- T1218.003

## Analytic Stories

- Ransomware
- Revil Ransomware
- LockBit Ransomware

## Data Sources

- Sysmon EventID 7

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/revil/inf2/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/wbemprox_com_object_execution.yml)*
