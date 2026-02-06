# Windows Office Product Dropped Uncommon File

**Type:** Anomaly

**Author:** Teoderick Contreras, Michael Haag, Splunk, TheLawsOfChaos, Github

## Description

The following analytic detects Microsoft Office applications dropping or creating executables or scripts on a Windows OS. It leverages process creation and file system events from the Endpoint data model to identify Office applications like Word or Excel generating files with extensions such as ".exe", ".dll", or ".ps1". This behavior is significant as it is often associated with spear-phishing attacks where malicious files are dropped to compromise the host. If confirmed malicious, this activity could lead to code execution, privilege escalation, or persistent access, posing a severe threat to the environment.

## MITRE ATT&CK

- T1566.001

## Analytic Stories

- CVE-2023-21716 Word RTF Heap Corruption
- Warzone RAT
- FIN7
- Compromised Windows Host
- AgentTesla
- PlugX

## Data Sources

- Sysmon EventID 1 AND Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/fin7/fin7_macro_js_1/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_office_product_dropped_uncommon_file.yml)*
