# Windows Phishing PDF File Executes URL Link

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects suspicious PDF viewer processes spawning browser application child processes. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process and parent process names. This activity is significant as it may indicate a PDF spear-phishing attempt where a malicious URL link is executed, leading to potential payload download. If confirmed malicious, this could allow attackers to execute code, escalate privileges, or persist in the environment by exploiting the user's browser to connect to a malicious site.

## MITRE ATT&CK

- T1566.001

## Analytic Stories

- Spearphishing Attachments
- Snake Keylogger

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/phishing_pdf_uri/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_phishing_pdf_file_executes_url_link.yml)*
