# DNS Exfiltration Using Nslookup App

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Wouter Jansen

## Description

The following analytic identifies potential DNS exfiltration using the nslookup application. It detects specific command-line parameters such as query type (TXT, A, AAAA) and retry options, which are commonly used by attackers to exfiltrate data. The detection leverages Endpoint Detection and Response (EDR) telemetry, focusing on process execution logs. This activity is significant as it may indicate an attempt to communicate with a Command and Control (C2) server or exfiltrate sensitive data. If confirmed malicious, this could lead to data breaches and unauthorized access to critical information.

## MITRE ATT&CK

- T1048

## Analytic Stories

- Suspicious DNS Traffic
- Dynamic DNS
- Data Exfiltration
- Command And Control
- Compromised Windows Host

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1048.003/nslookup_exfil/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/dns_exfiltration_using_nslookup_app.yml)*
