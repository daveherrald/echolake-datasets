# Disable UAC Remote Restriction

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

The following analytic detects the modification of the registry to disable UAC remote restriction by setting the "LocalAccountTokenFilterPolicy" value to "0x00000001". It leverages data from the Endpoint.Registry data model, specifically monitoring changes to the registry path "*\\CurrentVersion\\Policies\\System*". This activity is significant because disabling UAC remote restriction can allow an attacker to bypass User Account Control (UAC) protections, potentially leading to privilege escalation. If confirmed malicious, this could enable an attacker to execute unauthorized actions with elevated privileges, compromising the security of the affected system.

## MITRE ATT&CK

- T1548.002

## Analytic Stories

- Suspicious Windows Registry Activities
- Windows Defense Evasion Tactics
- CISA AA23-347A
- Windows Registry Abuse

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.002/LocalAccountTokenFilterPolicy/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/disable_uac_remote_restriction.yml)*
