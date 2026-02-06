# Windows RDP Bitmap Cache File Creation

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This detection identifies the creation of Remote Desktop Protocol (RDP) bitmap cache files on a Windows system, typically located in the user’s profile under the Terminal Server Client cache directory. These files (*.bmc, cache*.bin) are generated when a user initiates an RDP session using the built-in mstsc.exe client. Their presence can indicate interactive remote access activity and may be useful in detecting lateral movement or unauthorized RDP usage. Monitoring this behavior is especially important, as attackers may attempt to delete or suppress these artifacts to evade forensic analysis.

## MITRE ATT&CK

- T1021.001

## Analytic Stories

- Windows RDP Artifacts and Defense Evasion

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.001/bmc_creation/bmc_creation.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_rdp_bitmap_cache_file_creation.yml)*
