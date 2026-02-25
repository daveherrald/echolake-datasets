# Monitor Registry Keys for Print Monitors

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Steven Dick, Bhavin Patel

## Description

This dataset contains sample data for detecting modifications to the registry key `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors`. It leverages data from the Endpoint.Registry data model, focusing on events where the registry path is modified. This activity is significant because attackers can exploit this registry key to load arbitrary .dll files, which will execute with elevated SYSTEM permissions and persist after a reboot. If confirmed malicious, this could allow attackers to maintain persistence, execute code with high privileges, and potentially compromise the entire system.

## MITRE ATT&CK

- T1547.010

## Analytic Stories

- Suspicious Windows Registry Activities
- Windows Persistence Techniques
- Windows Registry Abuse

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.010/atomic_red_team/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/monitor_registry_keys_for_print_monitors.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
