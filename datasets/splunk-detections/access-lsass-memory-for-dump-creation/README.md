# Access LSASS Memory for Dump Creation

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting attempts to dump the LSASS process memory, a common technique in credential dumping attacks. It leverages Sysmon logs, specifically EventCode 10, to identify suspicious call traces to dbgcore.dll and dbghelp.dll associated with lsass.exe. This activity is significant as it often precedes the theft of sensitive login credentials, posing a high risk of unauthorized access to systems and data. If confirmed malicious, attackers could gain access to critical credentials, enabling further compromise and lateral movement within the network.

## MITRE ATT&CK

- T1003.001

## Analytic Stories

- CISA AA23-347A
- Credential Dumping
- Cactus Ransomware
- Lokibot
- Scattered Lapsus$ Hunters

## Data Sources

- Sysmon EventID 10

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/access_lsass_memory_for_dump_creation.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
