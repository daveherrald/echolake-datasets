# Windows Autostart Execution LSASS Driver Registry Modification

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects modifications to undocumented registry keys that allow a DLL to load into lsass.exe, potentially capturing credentials. It leverages the Endpoint.Registry data model to identify changes to \CurrentControlSet\Services\NTDS\DirectoryServiceExtPt or \CurrentControlSet\Services\NTDS\LsaDbExtPt. This activity is significant as it indicates a possible attempt to inject malicious code into the Local Security Authority Subsystem Service (LSASS), which can lead to credential theft. If confirmed malicious, this could allow attackers to gain unauthorized access to sensitive information and escalate privileges within the environment.

## MITRE ATT&CK

- T1547.008

## Analytic Stories

- Windows Registry Abuse

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.008/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_autostart_execution_lsass_driver_registry_modification.yml)*
