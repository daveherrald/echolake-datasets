# Icacls Deny Command

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects instances where an adversary modifies
security permissions of a file or directory using commands like "icacls.exe", "cacls.exe",
or "xcacls.exe" with deny options. It leverages data from Endpoint Detection and
Response (EDR) agents, focusing on process names and command-line executions. This
activity is significant as it is commonly used by Advanced Persistent Threats (APTs)
and coinminer scripts to evade detection and impede access to critical files. If
confirmed malicious, this could allow attackers to maintain persistence and hinder
incident response efforts.


## MITRE ATT&CK

- T1222

## Analytic Stories

- Azorult
- Sandworm Tools
- Compromised Windows Host
- XMRig
- Crypto Stealer
- Defense Evasion or Unauthorized Access Via SDDL Tampering

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/icacls_deny_command.yml)*
