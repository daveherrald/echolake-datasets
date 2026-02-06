# Windows Chromium Browser with Custom User Data Directory

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects instances where the Chromium-based browser (e.g., Google Chrome, Microsoft Edge) is launched with the --user-data-dir command-line argument. While this flag is legitimate and used for multi-profile support or automation, it is frequently leveraged by malware and adversaries to run Chrome in an isolated environment for stealth operations, credential harvesting, phishing delivery, or evasion of user session artifacts.


## MITRE ATT&CK

- T1497

## Analytic Stories

- StealC Stealer
- Malicious Inno Setup Loader
- Lokibot

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1497/chrom_no_sandbox/chrome-no_sandbox.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_chromium_browser_with_custom_user_data_directory.yml)*
