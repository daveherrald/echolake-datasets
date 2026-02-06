# Disable Defender Spynet Reporting

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

The following analytic detects the modification of the registry to disable Windows Defender SpyNet reporting. It leverages data from the Endpoint.Registry data model, specifically monitoring changes to the registry path associated with Windows Defender SpyNet settings. This activity is significant because disabling SpyNet reporting can prevent Windows Defender from sending telemetry data, potentially allowing malicious activities to go undetected. If confirmed malicious, this action could enable an attacker to evade detection, maintain persistence, and carry out further attacks without being flagged by Windows Defender.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Azorult
- Windows Registry Abuse
- Qakbot
- IcedID
- CISA AA23-347A

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/disable_av/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/disable_defender_spynet_reporting.yml)*
