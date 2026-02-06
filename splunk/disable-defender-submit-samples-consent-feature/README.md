# Disable Defender Submit Samples Consent Feature

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

The following analytic detects the modification of the Windows registry to disable the Windows Defender Submit Samples Consent feature. It leverages data from the Endpoint.Registry data model, specifically monitoring changes to the registry path associated with Windows Defender SpyNet and the SubmitSamplesConsent value set to 0x00000000. This activity is significant as it indicates an attempt to bypass or evade detection by preventing Windows Defender from submitting samples for further analysis. If confirmed malicious, this could allow an attacker to execute malicious code without being detected by Windows Defender, leading to potential system compromise.

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

*Source: [Splunk Security Content](detections/endpoint/disable_defender_submit_samples_consent_feature.yml)*
