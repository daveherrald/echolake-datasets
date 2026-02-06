# Windows Excessive Disabled Services Event

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies an excessive number of system events where services are modified from start to disabled. It leverages Windows Event Logs (EventCode 7040) to detect multiple service state changes on a single host. This activity is significant as it may indicate an adversary attempting to disable security applications or other critical services, potentially leading to defense evasion or destructive actions. If confirmed malicious, this behavior could allow attackers to disable security defenses, disrupt system operations, and achieve their objectives on the compromised system.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- CISA AA23-347A
- Compromised Windows Host
- Windows Defense Evasion Tactics

## Data Sources

- Windows Event Log System 7040

## Sample Data

- **Source:** XmlWinEventLog:System
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/windows_excessive_disabled_services_event/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_excessive_disabled_services_event.yml)*
