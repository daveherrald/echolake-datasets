# Advanced IP or Port Scanner Execution

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

The following analytic detects the execution of network scanning utilities such as Advanced IP Scanner or Advanced Port Scanner.
These legitimate administrative tools are often leveraged by threat actors and ransomware operators during the discovery phase to enumerate active hosts and open ports within a target environment.
Detection is based on process creation telemetry referencing known executable names, original file names, or specific command-line parameters such as "/portable" and "/lng" that are characteristic of these tools.
If confirmed malicious, this activity may indicate internal reconnaissance aimed at identifying reachable systems or services prior to lateral movement or further post-compromise actions.


## MITRE ATT&CK

- T1046
- T1135

## Analytic Stories

- Windows Defense Evasion Tactics

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1046/advanced_ip_port_scanner/advanced_ip_port_scanner.log


---

*Source: [Splunk Security Content](detections/endpoint/advanced_ip_or_port_scanner_execution.yml)*
