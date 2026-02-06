# Windows Drivers Loaded by Signature

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies all drivers being loaded on Windows systems using Sysmon EventCode 6 (Driver Load). It leverages fields such as driver path, signature status, and hash to detect potentially suspicious drivers. This activity is significant for a SOC as malicious drivers can be used to gain kernel-level access, bypass security controls, or persist in the environment. If confirmed malicious, this activity could allow an attacker to execute arbitrary code with high privileges, leading to severe system compromise and potential data exfiltration.

## MITRE ATT&CK

- T1014
- T1068

## Analytic Stories

- Windows Drivers
- CISA AA22-320A
- AgentTesla
- BlackByte Ransomware

## Data Sources

- Sysmon EventID 6

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1014/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_drivers_loaded_by_signature.yml)*
