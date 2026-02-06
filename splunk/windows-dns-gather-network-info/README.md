# Windows DNS Gather Network Info

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the use of the dnscmd.exe command to enumerate DNS records. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process command-line executions. This activity is significant as it may indicate an adversary gathering network information, a common precursor to more targeted attacks. If confirmed malicious, this behavior could enable attackers to map the network, identify critical assets, and plan subsequent actions, potentially leading to data exfiltration or further compromise of the network.

## MITRE ATT&CK

- T1590.002

## Analytic Stories

- Sandworm Tools
- Volt Typhoon

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1590.002/enum_dns_record/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_dns_gather_network_info.yml)*
