# Windows Process Injection In Non-Service SearchIndexer

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies instances of the searchindexer.exe process that are not spawned by services.exe, indicating potential process injection. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and parent processes. This activity is significant because QakBot malware often uses a fake searchindexer.exe to evade detection and perform malicious actions such as data exfiltration and keystroke logging. If confirmed malicious, this activity could allow attackers to maintain persistence, steal sensitive information, and communicate with command and control servers.

## MITRE ATT&CK

- T1055

## Analytic Stories

- Qakbot

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/non-service-searchindexer/seaarch-indexer-non-service.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_process_injection_in_non_service_searchindexer.yml)*
