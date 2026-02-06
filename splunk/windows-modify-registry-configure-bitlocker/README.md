# Windows Modify Registry Configure BitLocker

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This analytic is developed to detect suspicious registry modifications targeting BitLocker settings. The malware ShrinkLocker alters various registry keys to change how BitLocker handles encryption, potentially bypassing TPM requirements, enabling BitLocker without TPM, and enforcing specific startup key and PIN configurations. Such modifications can weaken system security, making it easier for unauthorized access and data breaches. Detecting these changes is crucial for maintaining robust encryption and data protection.

## MITRE ATT&CK

- T1112

## Analytic Stories

- ShrinkLocker

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/bitlocker_registry_setting//fve-reg.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_configure_bitlocker.yml)*
