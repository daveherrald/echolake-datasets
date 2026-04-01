# SecretDumps Offline NTDS Dumping Tool

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the potential use of the secretsdump.py tool to dump NTLM hashes from a copy of ntds.dit and the SAM, SYSTEM, and SECURITY registry hives. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on specific command-line patterns and process names associated with secretsdump.py. This activity is significant because it indicates an attempt to extract sensitive credential information offline, which is a common post-exploitation technique. If confirmed malicious, this could allow an attacker to obtain NTLM hashes, facilitating further lateral movement and potential privilege escalation within the network.

## MITRE ATT&CK

- T1003.003

## Analytic Stories

- Compromised Windows Host
- Graceful Wipe Out Attack
- Rhysida Ransomware
- Credential Dumping
- Storm-0501 Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/honeypots/casper/datasets1/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/secretdumps_offline_ntds_dumping_tool.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
