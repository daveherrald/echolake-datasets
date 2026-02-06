# Windows PowerShell Process Implementing Manual Base64 Decoder

**Type:** Anomaly

**Author:** Nasreddine Bencherchali

## Description

The following analytic identifies Windows PowerShell processes that implement a manual Base64 decoder.
Threat actors often use Base64 encoding to obfuscate malicious payloads or commands within PowerShell scripts.
By manually decoding Base64 strings, attackers can evade detection mechanisms that look for standard decoding functions like using the "-enc" flag or the "FromBase64String" function.
This detection focuses on PowerShell processes that exhibit characteristics of manual Base64 decoding, such as the presence of specific string manipulation methods and bitwise operations.
Security teams should investigate any instances of such activity, especially if found in conjunction with other suspicious behaviors or on systems that should not be using PowerShell for such tasks.


## MITRE ATT&CK

- T1027.010
- T1059.001

## Analytic Stories

- Compromised Windows Host
- Deobfuscate-Decode Files or Information

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://github.com/Splunk/attack_data/raw/master/datasets/attack_techniques/T1027.010/manual_b64_decode_pwsh/manual_b64_decode_pwsh.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_powershell_process_implementing_manual_base64_decoder.yml)*
