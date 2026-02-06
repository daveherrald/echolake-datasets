# Excessive Usage Of Taskkill

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies excessive usage of `taskkill.exe`, a command-line utility used to terminate processes. The detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on instances where `taskkill.exe` is executed ten or more times within a one-minute span. This behavior is significant as adversaries often use `taskkill.exe` to disable security tools or other critical processes to evade detection. If confirmed malicious, this activity could allow attackers to bypass security defenses, maintain persistence, and further compromise the system.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Azorult
- AgentTesla
- CISA AA22-277A
- NjRAT
- CISA AA22-264A
- XMRig
- Crypto Stealer

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/excessive_usage_of_taskkill.yml)*
