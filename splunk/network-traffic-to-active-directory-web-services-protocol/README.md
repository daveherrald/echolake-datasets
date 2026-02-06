# Network Traffic to Active Directory Web Services Protocol

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies network traffic directed to the Active Directory Web Services Protocol (ADWS) on port 9389. It leverages network traffic logs, focusing on source and destination IP addresses, application names, and destination ports. This activity is significant as ADWS is used to manage Active Directory, and unauthorized access could indicate malicious intent. If confirmed malicious, an attacker could manipulate Active Directory, potentially leading to privilege escalation, unauthorized access, or persistent control over the environment.

## MITRE ATT&CK

- T1069.001
- T1069.002
- T1087.001
- T1087.002
- T1482

## Analytic Stories

- Windows Discovery Techniques

## Data Sources

- Sysmon EventID 3

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/soaphound/sysmon_soaphound.log


---

*Source: [Splunk Security Content](detections/endpoint/network_traffic_to_active_directory_web_services_protocol.yml)*
