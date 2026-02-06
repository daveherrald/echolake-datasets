# Windows Defacement Modify Transcodedwallpaper File

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies modifications to the TranscodedWallpaper file in the wallpaper theme directory, excluding changes made by explorer.exe. This detection leverages the Endpoint.Processes and Endpoint.Filesystem data models to correlate process activity with file modifications. This activity is significant as it may indicate an adversary attempting to deface or change the desktop wallpaper of a targeted host, a tactic often used to signal compromise or deliver a message. If confirmed malicious, this could be a sign of unauthorized access and tampering, potentially leading to further system compromise or data exfiltration.

## MITRE ATT&CK

- T1491

## Analytic Stories

- Brute Ratel C4

## Data Sources

- Sysmon EventID 1 AND Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/brute_ratel/wallpaper_via_transcodedwallpaper/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_defacement_modify_transcodedwallpaper_file.yml)*
