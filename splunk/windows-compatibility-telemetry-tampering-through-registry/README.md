# Windows Compatibility Telemetry Tampering Through Registry

**Type:** TTP

**Author:** Steven Dick

## Description

This detection identifies suspicious modifications to the Windows Compatibility Telemetry registry settings, specifically within the "TelemetryController" registry key and "Command" registry value. It leverages data from the Endpoint.Registry data model, focusing on registry paths and values indicative of such changes. This activity is significant because CompatTelRunner.exe and the "Microsoft Compatibility Appraiser" task always run as System and can be used to elevate privileges or establish a highly privileged persistence mechanism. If confirmed malicious, this could enable unauthorized code execution, privilege escalation, or persistent access to the compromised system.

## MITRE ATT&CK

- T1546
- T1053.005

## Analytic Stories

- Windows Persistence Techniques

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546/compattelrunner_abuse/compattelrunner_abuse.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_compatibility_telemetry_tampering_through_registry.yml)*
