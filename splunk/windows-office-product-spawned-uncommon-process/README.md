# Windows Office Product Spawned Uncommon Process

**Type:** TTP

**Author:** Michael Haag, Teoderick Contreras, Splunk

## Description

The following analytic detects a Microsoft Office product spawning uncommon processes. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process creation events where Office applications are the parent process. This activity is significant as it may indicate an attempt of a malicious macro execution or exploitation of an unknown vulnerability in an office product, in order to bypass security controls. If confirmed malicious, this behavior could allow an attacker to execute arbitrary code, potentially leading to system compromise, data exfiltration, or further lateral movement within the network.

## MITRE ATT&CK

- T1566.001

## Analytic Stories

- AgentTesla
- Azorult
- Compromised Windows Host
- CVE-2023-21716 Word RTF Heap Corruption
- CVE-2023-36884 Office and Windows HTML RCE Vulnerability
- DarkCrystal RAT
- FIN7
- IcedID
- NjRAT
- PlugX
- Qakbot
- Remcos
- Spearphishing Attachments
- Trickbot
- Warzone RAT
- APT37 Rustonotto and FadeStealer

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/macro/windows-sysmon_macros.log

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/datasets/windows-sysmon.log

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/phish_icedid/windows-sysmon.log

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.002/atomic_red_team/windows-sysmon.log

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/trickbot/spear_phish/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_office_product_spawned_uncommon_process.yml)*
