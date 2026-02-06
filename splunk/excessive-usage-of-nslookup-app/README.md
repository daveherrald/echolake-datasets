# Excessive Usage of NSLOOKUP App

**Type:** Anomaly

**Author:** Teoderick Contreras, Stanislav Miskovic, Splunk

## Description

The following analytic detects excessive usage of the nslookup application, which may indicate potential DNS exfiltration attempts. It leverages Sysmon EventCode 1 to monitor process executions, specifically focusing on nslookup.exe. The detection identifies outliers by comparing the frequency of nslookup executions against a calculated threshold. This activity is significant as it can reveal attempts by malware or APT groups to exfiltrate data via DNS queries. If confirmed malicious, this behavior could allow attackers to stealthily transfer sensitive information out of the network, bypassing traditional data exfiltration defenses.

## MITRE ATT&CK

- T1048

## Analytic Stories

- Suspicious DNS Traffic
- Dynamic DNS
- Data Exfiltration
- Command And Control

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1048.003/nslookup_exfil/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/excessive_usage_of_nslookup_app.yml)*
