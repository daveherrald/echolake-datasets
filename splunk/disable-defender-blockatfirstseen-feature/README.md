# Disable Defender BlockAtFirstSeen Feature

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

The following analytic detects the modification of the Windows registry to disable the Windows Defender BlockAtFirstSeen feature. It leverages data from the Endpoint.Registry data model, specifically monitoring changes to the registry path associated with Windows Defender SpyNet and the DisableBlockAtFirstSeen value. This activity is significant because disabling this feature can allow malicious files to bypass initial detection by Windows Defender, increasing the risk of malware infection. If confirmed malicious, this action could enable attackers to execute malicious code undetected, leading to potential system compromise and data breaches.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Azorult
- CISA AA23-347A
- IcedID
- Windows Registry Abuse

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/disable_av/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/disable_defender_blockatfirstseen_feature.yml)*
