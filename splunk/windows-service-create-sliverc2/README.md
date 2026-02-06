# Windows Service Create SliverC2

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the creation of a Windows service named "Sliver" with the description "Sliver Implant," indicative of SliverC2 lateral movement using the PsExec module. It leverages Windows EventCode 7045 from the System Event log to identify this activity. This behavior is significant as it may indicate an adversary's attempt to establish persistence or execute commands remotely. If confirmed malicious, this activity could allow attackers to maintain control over the compromised system, execute arbitrary code, and further infiltrate the network.

## MITRE ATT&CK

- T1569.002

## Analytic Stories

- BishopFox Sliver Adversary Emulation Framework
- Compromised Windows Host
- Hellcat Ransomware

## Data Sources

- Windows Event Log System 7045

## Sample Data

- **Source:** XmlWinEventLog:System
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/sliver/sliver_windows-system.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_service_create_sliverc2.yml)*
