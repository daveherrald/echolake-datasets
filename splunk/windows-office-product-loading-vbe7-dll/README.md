# Windows Office Product Loading VBE7 DLL

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies office documents executing macro code. It leverages Sysmon EventCode 7 to detect when processes like WINWORD.EXE or EXCEL.EXE load specific DLLs associated with macros (e.g., VBE7.DLL). This activity is significant because macros are a common attack vector for delivering malicious payloads, such as malware. If confirmed malicious, this could lead to unauthorized code execution, data exfiltration, or further compromise of the system. Disabling macros by default is recommended to mitigate this risk.

## MITRE ATT&CK

- T1566.001

## Analytic Stories

- Spearphishing Attachments
- Trickbot
- IcedID
- DarkCrystal RAT
- AgentTesla
- Qakbot
- Azorult
- Remcos
- PlugX
- NjRAT

## Data Sources

- Sysmon EventID 7

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/datasets/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_office_product_loading_vbe7_dll.yml)*
