# Disabling Windows Local Security Authority Defences via Registry

**Type:** TTP

**Author:** Dean Luxton,Teoderick Contreras Splunk

## Description

The following analytic identifies the deletion of registry keys that disable Local Security Authority (LSA) protection and Microsoft Defender Device Guard. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on registry actions and paths associated with LSA and Device Guard settings. This activity is significant because disabling these defenses can leave a system vulnerable to various attacks, including credential theft and unauthorized code execution. If confirmed malicious, this action could allow attackers to bypass critical security mechanisms, leading to potential system compromise and persistent access.

## MITRE ATT&CK

- T1556

## Analytic Stories

- Windows Defense Evasion Tactics
- Windows Registry Abuse

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1556/disable_lsa_protection_new/lsa_reg_deletion_modification.log


---

*Source: [Splunk Security Content](detections/endpoint/disabling_windows_local_security_authority_defences_via_registry.yml)*
