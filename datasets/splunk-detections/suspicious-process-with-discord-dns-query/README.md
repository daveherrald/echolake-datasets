# Suspicious Process With Discord DNS Query

**Type:** Anomaly

**Author:** Teoderick Contreras, Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying a process making a DNS query to Discord, excluding legitimate Discord application paths. It leverages Sysmon logs with Event ID 22 to detect DNS queries containing "discord" in the QueryName field. This activity is significant because Discord can be abused by adversaries to host and download malicious files, as seen in the WhisperGate campaign. If confirmed malicious, this could indicate malware attempting to download additional payloads from Discord, potentially leading to further code execution and compromise of the affected system.

## MITRE ATT&CK

- T1059.005

## Analytic Stories

- Data Destruction
- WhisperGate
- PXA Stealer
- Cactus Ransomware

## Data Sources

- Sysmon EventID 22

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.005/discord_dnsquery/sysmon.log


---

*Source: [Splunk Security Content](detections/network/suspicious_process_with_discord_dns_query.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
