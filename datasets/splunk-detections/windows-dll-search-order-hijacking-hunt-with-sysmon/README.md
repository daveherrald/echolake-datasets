# Windows DLL Search Order Hijacking Hunt with Sysmon

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying potential DLL search order hijacking or DLL sideloading by detecting known Windows libraries loaded from non-standard directories. It leverages Sysmon EventCode 7 to monitor DLL loads and cross-references them with a lookup of known hijackable libraries. This activity is significant as it may indicate an attempt to execute malicious code by exploiting DLL search order vulnerabilities. If confirmed malicious, this could allow attackers to gain code execution, escalate privileges, or maintain persistence within the environment.

## MITRE ATT&CK

- T1574.001

## Analytic Stories

- Qakbot
- Windows Defense Evasion Tactics
- Living Off The Land
- Malicious Inno Setup Loader

## Data Sources

- Sysmon EventID 7

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1574.001/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_dll_search_order_hijacking_hunt_with_sysmon.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
