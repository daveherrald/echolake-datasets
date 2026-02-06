# Allow Operation with Consent Admin

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

The following analytic detects a registry modification that allows the 'Consent Admin' to perform operations requiring elevation without user consent or credentials. It leverages data from the Endpoint.Registry data model, specifically monitoring changes to the 'ConsentPromptBehaviorAdmin' value within the Windows Policies System registry path. This activity is significant as it indicates a potential privilege escalation attempt, which could allow an attacker to execute high-privilege tasks without user approval. If confirmed malicious, this could lead to unauthorized administrative access and control over the compromised machine, posing a severe security risk.

## MITRE ATT&CK

- T1548

## Analytic Stories

- Ransomware
- Windows Registry Abuse
- Azorult
- MoonPeak

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ransomware_ttp/data1/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/allow_operation_with_consent_admin.yml)*
