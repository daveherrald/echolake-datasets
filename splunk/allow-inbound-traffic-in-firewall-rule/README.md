# Allow Inbound Traffic In Firewall Rule

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects a suspicious PowerShell command that allows inbound traffic to a specific local port within the public profile. It leverages PowerShell script block logging (EventCode 4104) to identify commands containing keywords like "firewall," "Inbound," "Allow," and "-LocalPort." This activity is significant because it may indicate an attacker attempting to establish remote access by modifying firewall rules. If confirmed malicious, this could allow unauthorized access to the machine, potentially leading to further exploitation and data exfiltration.

## MITRE ATT&CK

- T1021.001

## Analytic Stories

- Prohibited Traffic Allowed or Protocol Mismatch
- NetSupport RMM Tool Abuse

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021/allow_inbound_traffic_in_firewall_rule/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/allow_inbound_traffic_in_firewall_rule.yml)*
