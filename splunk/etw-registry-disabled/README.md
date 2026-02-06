# ETW Registry Disabled

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

The following analytic detects a registry modification that disables the ETW for the .NET Framework. It leverages data from the Endpoint.Registry data model, specifically monitoring changes to the ETWEnabled registry value under the .NETFramework path. This activity is significant because disabling ETW can allow attackers to evade Endpoint Detection and Response (EDR) tools and hide their execution from audit logs. If confirmed malicious, this action could enable attackers to operate undetected, potentially leading to further compromise and persistent access within the environment.

## MITRE ATT&CK

- T1127
- T1562.006

## Analytic Stories

- Hermetic Wiper
- Windows Persistence Techniques
- Windows Privilege Escalation
- Windows Registry Abuse
- CISA AA23-347A
- Data Destruction

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1127/etw_disable/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/etw_registry_disabled.yml)*
