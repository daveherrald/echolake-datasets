# Registry Keys Used For Privilege Escalation

**Type:** TTP

**Author:** David Dorsey, Teoderick Contreras, Splunk, Steven Dick

## Description

The following analytic detects modifications to registry keys under "Image File Execution Options" that can be used for privilege escalation. It leverages data from the Endpoint.Registry data model, specifically monitoring changes to registry paths and values like GlobalFlag and Debugger. This activity is significant because attackers can use these modifications to intercept executable calls and attach malicious binaries to legitimate system binaries. If confirmed malicious, this could allow attackers to execute arbitrary code with elevated privileges, leading to potential system compromise and persistent access.

## MITRE ATT&CK

- T1546.012

## Analytic Stories

- Cloud Federated Credential Abuse
- Hermetic Wiper
- Windows Privilege Escalation
- Windows Registry Abuse
- Data Destruction
- Suspicious Windows Registry Activities

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.012/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/registry_keys_used_for_privilege_escalation.yml)*
