# Windows DLL Side-Loading In Calc

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects suspicious DLL modules loaded by calc.exe that are not located in the %systemroot%\system32 or %systemroot%\sysWoW64 directories. This detection leverages Sysmon EventCode 7 to identify DLL side-loading, a technique often used by Qakbot malware to execute malicious DLLs. This activity is significant as it indicates potential malware execution through a trusted process, which can bypass security controls. If confirmed malicious, this could allow attackers to execute arbitrary code, maintain persistence, and escalate privileges within the environment.

## MITRE ATT&CK

- T1574.001

## Analytic Stories

- Qakbot
- Earth Alux

## Data Sources

- Sysmon EventID 7

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/qakbot/qbot2/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_dll_side_loading_in_calc.yml)*
