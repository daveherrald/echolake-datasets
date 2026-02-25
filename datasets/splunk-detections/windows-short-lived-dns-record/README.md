# Windows Short Lived DNS Record

**Type:** TTP

**Author:** Raven Tait, Splunk

## Description

This dataset contains sample data for identifying the creation and quick deletion of a DNS object within 300 seconds in an Active Directory environment, indicative of a potential attack abusing DNS. This detection leverages Windows Security Event Codes 5136 and 5137, analyzing the duration between these events. This activity is significant as temporary DNS entries allows attackers to cause unexpecting network trafficking, leading to potential compromise.

## MITRE ATT&CK

- T1071.004
- T1557.001
- T1187

## Analytic Stories

- Compromised Windows Host
- Suspicious DNS Traffic
- Local Privilege Escalation With KrbRelayUp
- Kerberos Coercion with DNS

## Data Sources

- Windows Event Log Security 5136
- Windows Event Log Security 5137

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1071.004/kerberos_coercion/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_short_lived_dns_record.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
