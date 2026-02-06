# Windows Modify Registry AuthenticationLevelOverride

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects modifications to the Windows registry key "AuthenticationLevelOverride" within the Terminal Server Client settings. It leverages data from the Endpoint.Registry datamodel to identify changes where the registry value is set to 0x00000000. This activity is significant as it may indicate an attempt to override authentication levels for remote connections, a tactic used by DarkGate malware for malicious installations. If confirmed malicious, this could allow attackers to gain unauthorized remote access, potentially leading to data exfiltration or further system compromise.

## MITRE ATT&CK

- T1112

## Analytic Stories

- DarkGate Malware

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/AuthenticationLevelOverride/auth_sys.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_authenticationleveloverride.yml)*
