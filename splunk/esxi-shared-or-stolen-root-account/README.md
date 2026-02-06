# ESXi Shared or Stolen Root Account

**Type:** Anomaly

**Author:** Raven Tait, Splunk

## Description

This detection monitors for signs of a shared or potentially compromised root account on ESXi hosts by tracking the number of unique IP addresses logging in as root within a short time window. Multiple logins from different IPs in a brief period may indicate credential misuse, lateral movement, or account compromise.

## MITRE ATT&CK

- T1078

## Analytic Stories

- ESXi Post Compromise
- Black Basta Ransomware

## Data Sources

- VMWare ESXi Syslog

## Sample Data

- **Source:** vmware:esxlog
  **Sourcetype:** vmw-syslog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078/esxi_stolen_root_account/esxi_stolen_root_account.log


---

*Source: [Splunk Security Content](detections/application/esxi_shared_or_stolen_root_account.yml)*
