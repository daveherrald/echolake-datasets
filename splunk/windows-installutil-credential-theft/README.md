# Windows InstallUtil Credential Theft

**Type:** TTP

**Author:** Michael Haag, Mauricio Velazo, Splunk

## Description

The following analytic detects instances where the Windows InstallUtil.exe binary loads `vaultcli.dll` and `Samlib.dll`. This detection leverages Sysmon EventCode 7 to identify these specific DLL loads. This activity is significant because it can indicate an attempt to execute code that bypasses application control and captures credentials using tools like Mimikatz. If confirmed malicious, this behavior could allow an attacker to steal credentials, potentially leading to unauthorized access and further compromise of the system.

## MITRE ATT&CK

- T1218.004

## Analytic Stories

- Signed Binary Proxy Execution InstallUtil

## Data Sources

- Sysmon EventID 7

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.004/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_installutil_credential_theft.yml)*
