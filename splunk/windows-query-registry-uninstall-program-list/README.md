# Windows Query Registry UnInstall Program List

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects an access request on the uninstall registry key. It leverages Windows Security Event logs, specifically event code 4663. This activity is significant because adversaries or malware can exploit this key to gather information about installed applications, aiding in further attacks. If confirmed malicious, this behavior could allow attackers to map out installed software, potentially identifying vulnerabilities or software to exploit, leading to further system compromise.

## MITRE ATT&CK

- T1012

## Analytic Stories

- StealC Stealer
- RedLine Stealer
- Meduza Stealer

## Data Sources

- Windows Event Log Security 4663

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/redline/recon_registry/recon-reg-redline-security-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_query_registry_uninstall_program_list.yml)*
