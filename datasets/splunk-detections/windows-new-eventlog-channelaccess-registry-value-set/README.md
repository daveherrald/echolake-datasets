# Windows New EventLog ChannelAccess Registry Value Set

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Michael Haag, Splunk

## Description

This dataset contains sample data for detecting suspicious modifications to the EventLog security descriptor registry value for defense evasion. It leverages data from the Endpoint.Registry data model, focusing on changes to the "CustomSD" value within the "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Eventlog\<Channel>\CustomSD" path. This activity is significant as changes to the access permissions of the event log could blind security products and help attackers evade defenses. If confirmed malicious, this could allow attackers to block users and security products from viewing, ingesting and interacting event logs.

## MITRE ATT&CK

- T1562.002

## Analytic Stories

- LockBit Ransomware
- Defense Evasion or Unauthorized Access Via SDDL Tampering

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.002/eventlog_sddl_tampering/eventlog_sddl_tampering_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_new_eventlog_channelaccess_registry_value_set.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
