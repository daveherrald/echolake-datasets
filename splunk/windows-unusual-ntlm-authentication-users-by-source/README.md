# Windows Unusual NTLM Authentication Users By Source

**Type:** Anomaly

**Author:** Steven Dick

## Description

The following analytic detects when an unusual number of NTLM authentications is attempted by the same source. This activity generally results when an attacker attempts to brute force, password spray, or otherwise authenticate to a domain joined Windows device using an NTLM based process/attack. This same activity may also generate a large number of EventID 4776 events in as well.

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

*Source: [Splunk Security Content](detections/endpoint/windows_unusual_ntlm_authentication_users_by_source.yml)*
