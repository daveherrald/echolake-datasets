# Windows SqlWriter SQLDumper DLL Sideload

**Type:** TTP

**Author:** Michael Haag, Teoderick Contreras, Splunk

## Description

The following analytic detects the abuse of SqlWriter and SQLDumper executables to sideload the vcruntime140.dll library. It leverages Sysmon EventCode 7 logs, focusing on instances where SQLDumper.exe or SQLWriter.exe load vcruntime140.dll, excluding legitimate loads from the System32 directory. This activity is significant as it indicates potential DLL sideloading, a technique used by adversaries to execute malicious code within trusted processes. If confirmed malicious, this could allow attackers to execute arbitrary code, maintain persistence, and evade detection by blending with legitimate processes.

## MITRE ATT&CK

- T1574.001

## Analytic Stories

- APT29 Diplomatic Deceptions with WINELOADER

## Data Sources

- Sysmon EventID 7

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1574.002/wineloader/sqlwriter_sqldumper_sideload_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_sqlwriter_sqldumper_dll_sideload.yml)*
