# Windows LSA Secrets NoLMhash Registry

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects modifications to the Windows registry related to the Local Security Authority (LSA) NoLMHash setting. It identifies when the registry value is set to 0, indicating that the system will store passwords in the weaker Lan Manager (LM) hash format. This detection leverages registry activity logs from endpoint data sources like Sysmon or EDR tools. Monitoring this activity is crucial as it can indicate attempts to weaken password storage security. If confirmed malicious, this could allow attackers to exploit weaker LM hashes, potentially leading to unauthorized access and credential theft.

## MITRE ATT&CK

- T1003.004

## Analytic Stories

- CISA AA23-347A
- Scattered Lapsus$ Hunters

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.004/NoLMHash/lsa-reg-settings-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_lsa_secrets_nolmhash_registry.yml)*
