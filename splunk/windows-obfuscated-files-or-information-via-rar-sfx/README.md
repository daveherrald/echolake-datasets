# Windows Obfuscated Files or Information via RAR SFX

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the creation of RAR Self-Extracting (SFX) files by monitoring the generation of file related to rar sfx .tmp file creation during sfx installation. This method leverages a heuristic to identify RAR SFX archives based on specific markers that indicate a combination of executable code and compressed RAR data. By tracking such activity, the analytic helps pinpoint potentially unauthorized or suspicious file creation events, which are often associated with malware packaging or data exfiltration. Legitimate usage may include custom installers or compressed file delivery.

## MITRE ATT&CK

- T1027.013

## Analytic Stories

- Crypto Stealer
- APT37 Rustonotto and FadeStealer
- GhostRedirector IIS Module and Rungan Backdoor

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1027.013/rar_sfx_execution/rar_sfx.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_obfuscated_files_or_information_via_rar_sfx.yml)*
