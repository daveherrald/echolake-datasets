# Windows AD Cross Domain SID History Addition

**Type:** TTP

**Author:** Dean Luxton

## Description

This dataset contains sample data for detecting changes to the sIDHistory attribute of user or computer objects across different domains. It leverages Windows Security Event Codes 4738 and 4742 to identify when the sIDHistory attribute is modified. This activity is significant because the sIDHistory attribute allows users to inherit permissions from other AD accounts, which can be exploited by adversaries for inter-domain privilege escalation and persistence. If confirmed malicious, this could enable attackers to gain unauthorized access to resources, maintain persistence, and escalate privileges across domain boundaries.

## MITRE ATT&CK

- T1134.005

## Analytic Stories

- Compromised Windows Host
- Sneaky Active Directory Persistence Tricks

## Data Sources

- Windows Event Log Security 4742
- Windows Event Log Security 4738

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1134.005/mimikatz/windows-security-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_ad_cross_domain_sid_history_addition.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
