# Windows Suspect Process With Authentication Traffic

**Type:** Anomaly

**Author:** Steven Dick

## Description

This dataset contains sample data for detecting executables running from public or temporary locations that are communicating over Windows domain authentication ports/protocols such as LDAP (389), LDAPS (636), and Kerberos (88). It leverages network traffic data to identify processes originating from user-controlled directories. This activity is significant because legitimate applications rarely run from these locations and attempt domain authentication, making it a potential indicator of compromise. If confirmed malicious, attackers could leverage this to access domain resources, potentially leading to further exploitation and lateral movement within the network.

## MITRE ATT&CK

- T1087.002
- T1204.002

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Sysmon EventID 3

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1649/certify_abuse/certify_esc1_abuse_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_suspect_process_with_authentication_traffic.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
