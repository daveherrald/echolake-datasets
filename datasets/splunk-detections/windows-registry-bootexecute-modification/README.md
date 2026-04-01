# Windows Registry BootExecute Modification

**Type:** TTP

**Author:** Michael Haag, Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting modifications to the BootExecute registry key, which manages applications and services executed during system boot. It leverages data from the Endpoint.Registry data model, focusing on changes to the registry path "HKLM\\System\\CurrentControlSet\\Control\\Session Manager\\BootExecute". This activity is significant because unauthorized changes to this key can indicate attempts to achieve persistence, load malicious code, or tamper with the boot process. If confirmed malicious, this could allow an attacker to maintain persistence, execute arbitrary code at boot, or disrupt system operations.

## MITRE ATT&CK

- T1542
- T1547.001

## Analytic Stories

- Windows BootKits

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.001/atomic_red_team/bootexecute-windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_registry_bootexecute_modification.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
