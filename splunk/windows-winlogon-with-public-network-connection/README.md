# Windows WinLogon with Public Network Connection

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

The following analytic detects instances of Winlogon.exe, a critical Windows process, connecting to public IP addresses. This behavior is identified using Endpoint Detection and Response (EDR) telemetry, focusing on network connections made by Winlogon.exe. Under normal circumstances, Winlogon.exe should not connect to public IPs, and such activity may indicate a compromise, such as the BlackLotus bootkit attack. This detection is significant as it highlights potential system integrity breaches. If confirmed malicious, attackers could maintain persistence, bypass security measures, and compromise the system at a fundamental level.

## MITRE ATT&CK

- T1542.003

## Analytic Stories

- BlackLotus Campaign

## Data Sources

- Sysmon EventID 1 AND Sysmon EventID 3

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1542.003/bootkits/network-winlogon-windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_winlogon_with_public_network_connection.yml)*
