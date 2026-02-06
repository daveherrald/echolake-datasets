# Windows Disable Internet Explorer Addons

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of iexplore.exe (Internet Explorer) with the -extoff command-line flag, which disables all browser extensions. This flag is commonly abused by adversaries to launch a clean browser session that bypasses security controls such as antivirus browser extensions, toolbars, or group policy-enforced add-ons.
Malicious documents or scripts may leverage iexplore.exe -extoff to open phishing pages, command-and-control interfaces, or download additional payloads in an environment free from security monitoring plugins. While this flag may be used legitimately by IT administrators for troubleshooting purposes, its use in modern enterprise environments is rare and should be considered suspicious—particularly when launched by Office applications, scripting engines (e.g., PowerShell, WScript), or scheduled tasks.


## MITRE ATT&CK

- T1176.001

## Analytic Stories

- Malicious Inno Setup Loader

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1176.001/disable_extension/iexplore-extoff.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_disable_internet_explorer_addons.yml)*
