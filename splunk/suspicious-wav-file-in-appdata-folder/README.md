# Suspicious WAV file in Appdata Folder

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the creation of .wav files in the AppData folder, a behavior associated with Remcos RAT malware, which stores audio recordings in this location for data exfiltration. The detection leverages endpoint process and filesystem data to identify .wav file creation within the AppData\Roaming directory. This activity is significant as it indicates potential unauthorized data collection and exfiltration by malware. If confirmed malicious, this could lead to sensitive information being sent to an attacker's command and control server, compromising the affected system's confidentiality.

## MITRE ATT&CK

- T1113

## Analytic Stories

- Remcos

## Data Sources

- Sysmon EventID 1 AND Sysmon EventID 11
- Windows Event Log Security 4688 AND Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/remcos/remcos_agent/sysmon_wav.log


---

*Source: [Splunk Security Content](detections/endpoint/suspicious_wav_file_in_appdata_folder.yml)*
