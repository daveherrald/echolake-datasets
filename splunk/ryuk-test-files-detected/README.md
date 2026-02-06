# Ryuk Test Files Detected

**Type:** TTP

**Author:** Rod Soto, Jose Hernandez, Splunk

## Description

The following analytic identifies the presence of files containing the keyword "Ryuk" in any folder on the C drive, indicative of Ryuk ransomware activity. It leverages the Endpoint Filesystem data model to detect file paths matching this pattern. This activity is significant as Ryuk ransomware is known for its destructive impact, encrypting critical files and demanding ransom. If confirmed malicious, this could lead to significant data loss, operational disruption, and financial damage due to ransom payments and recovery efforts. Immediate investigation and response are crucial to mitigate potential damage.

## MITRE ATT&CK

- T1486

## Analytic Stories

- Ryuk Ransomware

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ryuk/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/ryuk_test_files_detected.yml)*
