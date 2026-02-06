# Windows Modify System Firewall with Notable Process Path

**Type:** TTP

**Author:** Teoderick Contreras, Will Metcalf, Splunk

## Description

The following analytic detects suspicious modifications to system firewall rules, specifically allowing execution of applications from notable and potentially malicious file paths. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions involving firewall rule changes. This activity is significant as it may indicate an adversary attempting to bypass firewall restrictions to execute malicious files. If confirmed malicious, this could allow attackers to execute unauthorized code, potentially leading to further system compromise, data exfiltration, or persistence within the environment.

## MITRE ATT&CK

- T1562.004

## Analytic Stories

- Medusa Ransomware
- NjRAT
- Compromised Windows Host

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.004/njrat_add_firewall_rule/njrat_firewall_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_system_firewall_with_notable_process_path.yml)*
