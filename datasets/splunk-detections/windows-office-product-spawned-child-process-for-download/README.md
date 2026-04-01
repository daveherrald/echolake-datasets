# Windows Office Product Spawned Child Process For Download

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying Office applications spawning child processes to download content via HTTP/HTTPS. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process creation events where Office applications like Word or Excel initiate network connections, excluding common browsers. This activity is significant as it often indicates the use of malicious documents to execute living-off-the-land binaries (LOLBins) for payload delivery. If confirmed malicious, this behavior could lead to unauthorized code execution, data exfiltration, or further malware deployment, posing a severe threat to the organization's security.

## MITRE ATT&CK

- T1566.001

## Analytic Stories

- Spearphishing Attachments
- CVE-2023-36884 Office and Windows HTML RCE Vulnerability
- PlugX
- NjRAT
- APT37 Rustonotto and FadeStealer

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/datasets2/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_office_product_spawned_child_process_for_download.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
