# ESXi Account Modified

**Type:** Anomaly

**Author:** Raven Tait, Splunk

## Description

This detection identifies the creation, deletion, or modification of a local user account on an ESXi host. This activity may indicate unauthorized access, indicator removal, or persistence attempts by an attacker seeking to establish or maintain control of the host.

## MITRE ATT&CK

- T1136.001
- T1078
- T1098

## Analytic Stories

- ESXi Post Compromise
- Black Basta Ransomware

## Data Sources

- VMWare ESXi Syslog

## Sample Data

- **Source:** vmware:esxlog
  **Sourcetype:** vmw-syslog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/esxi_account_modification/esxi_account_modified.log


---

*Source: [Splunk Security Content](detections/application/esxi_account_modified.yml)*
