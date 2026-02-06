# Registry Keys for Creating SHIM Databases

**Type:** TTP

**Author:** Patrick Bareiss, Teoderick Contreras, Splunk, Steven Dick, Bhavin Patel

## Description

The following analytic detects registry activity related to the creation of application compatibility shims. It leverages data from the Endpoint.Registry data model, specifically monitoring registry paths associated with AppCompatFlags. This activity is significant because attackers can use shims to bypass security controls, achieve persistence, or escalate privileges. If confirmed malicious, this could allow an attacker to maintain long-term access, execute arbitrary code, or manipulate application behavior, posing a severe risk to the integrity and security of the affected systems.

## MITRE ATT&CK

- T1546.011

## Analytic Stories

- Suspicious Windows Registry Activities
- Windows Persistence Techniques
- Windows Registry Abuse

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.011/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/registry_keys_for_creating_shim_databases.yml)*
