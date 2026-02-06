# DNS Query Length With High Standard Deviation

**Type:** Anomaly

**Author:** Bhavin Patel, Splunk

## Description

The following analytic identifies DNS queries with unusually large lengths by computing the standard deviation of query lengths and filtering those exceeding two times the standard deviation. It leverages DNS query data from the Network_Resolution data model, focusing on the length of the domain names being resolved. This activity is significant as unusually long DNS queries can indicate data exfiltration or command-and-control communication attempts. If confirmed malicious, this activity could allow attackers to stealthily transfer data or maintain persistent communication channels within the network.

## MITRE ATT&CK

- T1048.003

## Analytic Stories

- Hidden Cobra Malware
- Suspicious DNS Traffic
- Command And Control

## Data Sources

- Sysmon EventID 22

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1071.004/long_dns_query/dns-sysmon.log


---

*Source: [Splunk Security Content](detections/network/dns_query_length_with_high_standard_deviation.yml)*
