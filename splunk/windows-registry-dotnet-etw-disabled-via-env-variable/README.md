# Windows Registry Dotnet ETW Disabled Via ENV Variable

**Type:** TTP

**Author:** Nasreddine Bencherchali, Splunk

## Description

The following analytic detects a registry modification that disables the ETW for the .NET Framework. It leverages data from the Endpoint.Registry data model, specifically monitoring changes to the COMPlus_ETWEnabled registry value under the "Environment" registry key path for both user (HKCU\Environment) and machine (HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment) scopes. This activity is significant because disabling ETW can allow attackers to evade Endpoint Detection and Response (EDR) tools and hide their execution from audit logs. If confirmed malicious, this action could enable attackers to operate undetected, potentially leading to further compromise and persistent access within the environment.

## MITRE ATT&CK

- T1562.006

## Analytic Stories

- Windows Registry Abuse
- Windows Defense Evasion Tactics

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.006/dotnet_etw_bypass/dotnet_etw_bypass.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_registry_dotnet_etw_disabled_via_env_variable.yml)*
