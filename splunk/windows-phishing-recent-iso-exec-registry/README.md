# Windows Phishing Recent ISO Exec Registry

**Type:** Hunting

**Author:** Teoderick Contreras, Bhavin Patel, Splunk

## Description

The following analytic detects the creation of registry artifacts when an ISO container is opened, clicked, or mounted on a Windows operating system. It leverages data from the Endpoint.Registry data model, specifically monitoring registry keys related to recent ISO or IMG file executions. This activity is significant as adversaries increasingly use container-based phishing campaigns to bypass macro-based document execution controls. If confirmed malicious, this behavior could indicate an initial access attempt, potentially leading to further exploitation, persistence, or data exfiltration within the environment.

## MITRE ATT&CK

- T1566.001

## Analytic Stories

- Brute Ratel C4
- AgentTesla
- Qakbot
- IcedID
- Azorult
- Remcos
- Warzone RAT
- Gozi Malware

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/brute_ratel/iso_version_dll_campaign/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_phishing_recent_iso_exec_registry.yml)*
