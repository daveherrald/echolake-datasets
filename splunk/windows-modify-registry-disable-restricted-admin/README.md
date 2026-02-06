# Windows Modify Registry Disable Restricted Admin

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects modifications to the Windows registry entry "DisableRestrictedAdmin," which controls the Restricted Admin mode behavior. This detection leverages registry activity logs from endpoint data sources like Sysmon or Carbon Black. Monitoring this activity is crucial as changes to this setting can disable a security feature that limits credential exposure during remote connections. If confirmed malicious, an attacker could weaken security controls, increasing the risk of credential theft and unauthorized access to sensitive systems.

## MITRE ATT&CK

- T1112

## Analytic Stories

- GhostRedirector IIS Module and Rungan Backdoor
- Medusa Ransomware
- CISA AA23-347A

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.004/NoLMHash/lsa-reg-settings-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_disable_restricted_admin.yml)*
