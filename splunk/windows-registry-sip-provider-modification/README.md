# Windows Registry SIP Provider Modification

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects modifications to the Windows Registry SIP Provider. It leverages Sysmon EventID 7 to monitor registry changes in paths and values related to Cryptography Providers and OID Encoding Types. This activity is significant as it may indicate an attempt to subvert trust controls, a common tactic for bypassing security measures and maintaining persistence. If confirmed malicious, an attacker could manipulate the system's cryptographic functions, potentially leading to unauthorized access, data theft, or other damaging outcomes. Review the modified registry paths and concurrent processes to identify the attack source.

## MITRE ATT&CK

- T1553.003

## Analytic Stories

- Subvert Trust Controls SIP and Trust Provider Hijacking

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1553.003/sip/sip_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_registry_sip_provider_modification.yml)*
