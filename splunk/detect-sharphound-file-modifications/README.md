# Detect SharpHound File Modifications

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the creation of files typically associated with SharpHound, a reconnaissance tool used for gathering domain and trust data. It leverages file modification events from the Endpoint.Filesystem data model, focusing on default file naming patterns like `*_BloodHound.zip` and various JSON files. This activity is significant as it indicates potential domain enumeration, which is a precursor to more targeted attacks. If confirmed malicious, an attacker could gain detailed insights into the domain structure, facilitating lateral movement and privilege escalation.

## MITRE ATT&CK

- T1069.001
- T1069.002
- T1087.001
- T1087.002
- T1482

## Analytic Stories

- Windows Discovery Techniques
- Ransomware
- BlackSuit Ransomware

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/sharphound/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_sharphound_file_modifications.yml)*
