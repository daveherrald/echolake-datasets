# UAC Bypass MMC Load Unsigned Dll

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the loading of an unsigned DLL by the MMC.exe application, which is indicative of a potential UAC bypass or privilege escalation attempt. It leverages Sysmon EventCode 7 to identify instances where MMC.exe loads a non-Microsoft, unsigned DLL. This activity is significant because attackers often use this technique to modify CLSID registry entries, causing MMC.exe to load malicious DLLs, thereby bypassing User Account Control (UAC) and gaining elevated privileges. If confirmed malicious, this could allow an attacker to execute arbitrary code with higher privileges, leading to further system compromise and persistence.

## MITRE ATT&CK

- T1218.014
- T1548.002

## Analytic Stories

- Windows Defense Evasion Tactics

## Data Sources

- Sysmon EventID 7

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/uac_bypass/windows-sysmon2.log


---

*Source: [Splunk Security Content](detections/endpoint/uac_bypass_mmc_load_unsigned_dll.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
