# Windows Gather Victim Host Information Camera

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects a PowerShell script that enumerates camera devices on the targeted host. This detection leverages PowerShell Script Block Logging, specifically looking for commands querying Win32_PnPEntity for camera-related information. This activity is significant as it is commonly observed in DCRat malware, which collects camera data to send to its command-and-control server. If confirmed malicious, this behavior could indicate an attempt to gather sensitive visual information from the host, potentially leading to privacy breaches or further exploitation.

## MITRE ATT&CK

- T1592.001

## Analytic Stories

- DarkCrystal RAT

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/dcrat/dcrat_enum_camera/windows-powershell-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_gather_victim_host_information_camera.yml)*
