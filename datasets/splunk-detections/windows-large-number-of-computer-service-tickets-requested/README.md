# Windows Large Number of Computer Service Tickets Requested

**Type:** Anomaly

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting a high volume of Kerberos service ticket requests, specifically more than 30, from a single source within a 5-minute window. It leverages Event ID 4769, which logs when a Kerberos service ticket is requested, focusing on requests with computer names as the Service Name. This behavior is significant as it may indicate malicious activities such as lateral movement, malware staging, or reconnaissance. If confirmed malicious, an attacker could gain unauthorized access to multiple endpoints, potentially compromising the entire network.

## MITRE ATT&CK

- T1135
- T1078

## Analytic Stories

- Active Directory Privilege Escalation
- Active Directory Lateral Movement

## Data Sources

- Windows Event Log Security 4769

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1135/large_number_computer_service_tickets/windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_large_number_of_computer_service_tickets_requested.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
