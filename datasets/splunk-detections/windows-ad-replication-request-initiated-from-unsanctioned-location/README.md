# Windows AD Replication Request Initiated from Unsanctioned Location

**Type:** TTP

**Author:** Dean Luxton

## Description

This dataset contains sample data for identifying unauthorized Active Directory replication requests initiated from non-domain controller locations. It leverages EventCode 4662 to detect when a computer account with replication permissions creates a handle to domainDNS, filtering out known domain controller IP addresses. This activity is significant as it may indicate a DCSync attack, where an attacker with privileged access can request password hashes for any or all users within the domain. If confirmed malicious, this could lead to unauthorized access to sensitive information and potential full domain compromise.

## MITRE ATT&CK

- T1003.006

## Analytic Stories

- Compromised Windows Host
- Sneaky Active Directory Persistence Tricks
- Credential Dumping

## Data Sources

- Windows Event Log Security 4662
- Windows Event Log Security 4624

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.006/impacket/windows-security-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_ad_replication_request_initiated_from_unsanctioned_location.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
