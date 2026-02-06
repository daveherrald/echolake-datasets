# Windows Spearphishing Attachment Onenote Spawn Mshta

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects OneNote spawning `mshta.exe`, a behavior often associated with spearphishing attacks. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process creation events where OneNote is the parent process. This activity is significant as it is commonly used by malware families like TA551, AsyncRat, Redline, and DCRAT to execute malicious scripts. If confirmed malicious, this could allow attackers to execute arbitrary code, potentially leading to data exfiltration, system compromise, or further malware deployment. Immediate investigation and containment are recommended.

## MITRE ATT&CK

- T1566.001

## Analytic Stories

- Spearphishing Attachments
- Compromised Windows Host
- AsyncRAT
- APT37 Rustonotto and FadeStealer

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/onenote_spear_phishing/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_spearphishing_attachment_onenote_spawn_mshta.yml)*
