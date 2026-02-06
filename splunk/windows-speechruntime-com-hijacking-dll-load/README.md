# Windows SpeechRuntime COM Hijacking DLL Load

**Type:** TTP

**Author:** Raven Tait, Splunk

## Description

SpeechRuntime is vulnerable to an attack that allows a user to run code on another user's session remotely and stealthily by exploiting a Windows COM class. When this class is invoked, it launches SpeechRuntime.exe in the context of the currently logged-on user. Because this COM class is susceptible to COM Hijacking, the attacker can alter the registry remotely to point to a malicious DLL. By dropping that DLL on the target system (e.g., via SMB) and triggering the COM object, the attacker causes the malicious DLL to load into SpeechRuntime.exe and executing under the user's context. This detection identifies suspicious DLL loads by SpeechRuntime.exe from outside the expected locations.

## MITRE ATT&CK

- T1021.003

## Analytic Stories

- Active Directory Lateral Movement
- Compromised Windows Host
- Scattered Lapsus$ Hunters

## Data Sources

- Sysmon EventID 7

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.003/lateral_movement_speechruntime/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_speechruntime_com_hijacking_dll_load.yml)*
