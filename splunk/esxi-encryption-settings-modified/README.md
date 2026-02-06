# ESXi Encryption Settings Modified

**Type:** TTP

**Author:** Raven Tait, Splunk

## Description

Detects the disabling of critical encryption enforcement settings on an ESXi host, such as secure boot or executable verification requirements, which may indicate an attempt to weaken hypervisor integrity or allow unauthorized code execution.

## MITRE ATT&CK

- T1562

## Analytic Stories

- ESXi Post Compromise
- Black Basta Ransomware

## Data Sources

- VMWare ESXi Syslog

## Sample Data

- **Source:** vmware:esxlog
  **Sourcetype:** vmw-syslog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562/esxi_encryption_modified/esxi_encryption_modified.log


---

*Source: [Splunk Security Content](detections/application/esxi_encryption_settings_modified.yml)*
