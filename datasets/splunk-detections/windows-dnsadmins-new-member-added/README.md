# Windows DnsAdmins New Member Added

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the addition of a new member to the DnsAdmins group in Active Directory by leveraging Event ID 4732. This detection uses security event logs to identify changes to this high-privilege group. Monitoring this activity is crucial because members of the DnsAdmins group can manage the DNS service, often running on Domain Controllers, and potentially execute malicious code with SYSTEM privileges. If confirmed malicious, this activity could allow an attacker to escalate privileges and gain control over critical domain services, posing a significant security risk.

## MITRE ATT&CK

- T1098

## Analytic Stories

- Active Directory Privilege Escalation

## Data Sources

- Windows Event Log Security 4732

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/dnsadmins_member_added/windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_dnsadmins_new_member_added.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
