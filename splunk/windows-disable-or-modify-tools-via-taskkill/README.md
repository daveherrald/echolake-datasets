# Windows Disable or Modify Tools Via Taskkill

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies the use of taskkill.exe to forcibly terminate processes. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions that include specific taskkill parameters. This activity is significant because it can indicate attempts to disable security tools or disrupt legitimate applications, a common tactic in malware operations. If confirmed malicious, this behavior could allow attackers to evade detection, disrupt system stability, and potentially gain further control over the compromised system.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- PXA Stealer
- NjRAT
- Crypto Stealer

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/taskkill/taskkill_im.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_disable_or_modify_tools_via_taskkill.yml)*
