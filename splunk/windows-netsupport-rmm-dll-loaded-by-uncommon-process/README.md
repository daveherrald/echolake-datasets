# Windows NetSupport RMM DLL Loaded By Uncommon Process

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the loading of specific dynamic-link libraries (DLLs) associated with the NetSupport Remote Manager (RMM) tool by any process on a Windows system.
Modules such as CryptPak.dll, HTCTL32.DLL, IPCTL32.DLL, keyshowhook.dll, pcicapi.DLL, PCICL32.DLL, and TCCTL32.DLL, are integral to NetSupport's functionality.
This detection is particularly valuable when these modules are loaded by processes running from unusual directories (e.g., Downloads, ProgramData, or user-specific folders) rather than the legitimate Program Files installation path, or by executables that have been renamed but retain the internal "client32" identifier.
This helps to identify instances where the legitimate NetSupport tool is being misused by adversaries as a Remote Access Trojan (RAT).


## MITRE ATT&CK

- T1036

## Analytic Stories

- NetSupport RMM Tool Abuse

## Data Sources

- Sysmon EventID 7

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036/netsupport_modules/net_support_module.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_netsupport_rmm_dll_loaded_by_uncommon_process.yml)*
