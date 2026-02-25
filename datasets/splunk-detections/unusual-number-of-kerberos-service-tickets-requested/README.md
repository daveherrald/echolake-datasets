# Unusual Number of Kerberos Service Tickets Requested

**Type:** Anomaly

**Author:** Mauricio Velazco, Dean Luxton, Splunk

## Description

This dataset contains sample data for identifying an unusual number of Kerberos service ticket requests, potentially indicating a kerberoasting attack. It leverages Kerberos Event 4769 and calculates the standard deviation for each host, using the 3-sigma rule to detect anomalies. This activity is significant as kerberoasting allows adversaries to request service tickets and crack them offline, potentially gaining privileged access to the domain. If confirmed malicious, this could lead to unauthorized access to sensitive accounts and escalation of privileges within the Active Directory environment.

## MITRE ATT&CK

- T1558.003

## Analytic Stories

- Active Directory Kerberos Attacks

## Data Sources

- Windows Event Log Security 4769

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558.003/unusual_number_of_kerberos_service_tickets_requested/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/unusual_number_of_kerberos_service_tickets_requested.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
