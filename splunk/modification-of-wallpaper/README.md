# Modification Of Wallpaper

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the modification of registry keys related to the desktop wallpaper settings. It leverages Sysmon EventCode 13 to identify changes to the "Control Panel\\Desktop\\Wallpaper" and "Control Panel\\Desktop\\WallpaperStyle" registry keys, especially when the modifying process is not explorer.exe or involves suspicious file paths like temp or public directories. This activity is significant as it can indicate ransomware behavior, such as the REVIL ransomware, which changes the wallpaper to display a ransom note. If confirmed malicious, this could signify a compromised machine and the presence of ransomware, leading to potential data encryption and extortion.

## MITRE ATT&CK

- T1491

## Analytic Stories

- Revil Ransomware
- Rhysida Ransomware
- LockBit Ransomware
- BlackMatter Ransomware
- Brute Ratel C4
- Windows Registry Abuse
- Black Basta Ransomware
- Ransomware

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/revil/inf1/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/modification_of_wallpaper.yml)*
