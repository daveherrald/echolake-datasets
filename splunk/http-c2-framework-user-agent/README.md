# HTTP C2 Framework User Agent

**Type:** TTP

**Author:** Ravent Tait, Splunk

## Description

This Splunk query analyzes web logs to identify and categorize user agents, detecting various types of c2 frameworks. This activity can signify malicious actors attempting to interact with hosts on the network using known default configurations of command and control tools.

## MITRE ATT&CK

- T1071.001

## Analytic Stories

- Cobalt Strike
- Brute Ratel C4
- Tuoni
- Meterpreter
- Spearphishing Attachments
- Malicious PowerShell
- BishopFox Sliver Adversary Emulation Framework
- Suspicious User Agents

## Data Sources

- Suricata

## Sample Data

- **Source:** suricata
  **Sourcetype:** suricata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1071.001/http_user_agents/suricata_c2.log


---

*Source: [Splunk Security Content](detections/network/http_c2_framework_user_agent.yml)*
