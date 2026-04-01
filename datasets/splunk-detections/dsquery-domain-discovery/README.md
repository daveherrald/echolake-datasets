# DSQuery Domain Discovery

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the execution of "dsquery.exe" with arguments targeting `TrustedDomain` queries directly from the command line. This behavior is identified using Endpoint Detection and Response (EDR) telemetry, focusing on process names and command-line arguments. This activity is significant as it often indicates domain trust discovery, a common step in lateral movement or privilege escalation by adversaries. If confirmed malicious, this could allow attackers to map domain trusts, potentially leading to further exploitation and unauthorized access to trusted domains.

## MITRE ATT&CK

- T1482

## Analytic Stories

- Active Directory Discovery
- Domain Trust Discovery
- Compromised Windows Host

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1482/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/dsquery_domain_discovery.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
