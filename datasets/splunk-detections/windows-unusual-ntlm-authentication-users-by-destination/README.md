# Windows Unusual NTLM Authentication Users By Destination

**Type:** Anomaly

**Author:** Steven Dick

## Description

This dataset contains sample data for detecting when a device is the target of numerous NTLM authentications using a null domain. This activity generally results when an attacker attempts to brute force, password spray, or otherwise authenticate to a domain joined Windows device from a non-domain device. This activity may also generate a large number of EventID 4776 events in tandem, however these events will not indicate the attacker or target device.

## MITRE ATT&CK

- T1110.003

## Analytic Stories

- Active Directory Password Spraying

## Data Sources

- NTLM Operational 8004
- NTLM Operational 8005
- NTLM Operational 8006

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-NTLM/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/ntlm_bruteforce/ntlm_bruteforce.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_unusual_ntlm_authentication_users_by_destination.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
