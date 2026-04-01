# Disable Defender Submit Samples Consent Feature

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

This dataset contains sample data for detecting the modification of the Windows registry to disable the Windows Defender Submit Samples Consent feature. It leverages data from the Endpoint.Registry data model, specifically monitoring changes to the registry path associated with Windows Defender SpyNet and the SubmitSamplesConsent value set to 0x00000000. This activity is significant as it indicates an attempt to bypass or evade detection by preventing Windows Defender from submitting samples for further analysis. If confirmed malicious, this could allow an attacker to execute malicious code without being detected by Windows Defender, leading to potential system compromise.

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


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
