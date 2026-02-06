# Windows RDPClient Connection Sequence Events

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

This analytic monitors Windows RDP client connection sequence events (EventCode 1024) from the Microsoft-Windows-TerminalServices-RDPClient/Operational log. These events track when RDP ClientActiveX initiates connection attempts to remote servers. The connection sequence is a critical phase of RDP where the client and server exchange settings and establish common parameters for the session. Monitoring these events can help identify unusual RDP connection patterns, potential lateral movement attempts, unauthorized remote access activity, and RDP connection chains that may indicate compromised systems. NOTE the analytic was written for Multi-Line as XML was not properly parsed out.

## MITRE ATT&CK

- T1133

## Analytic Stories

- Spearphishing Attachments
- Windows RDP Artifacts and Defense Evasion

## Data Sources

- Windows Event Log Microsoft Windows TerminalServices RDPClient 1024

## Sample Data

- **Source:** WinEventLog:Microsoft-Windows-TerminalServices-RDPClient/Operational
  **Sourcetype:** WinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1133/rdp/terminalservices-rdpclient.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_rdpclient_connection_sequence_events.yml)*
