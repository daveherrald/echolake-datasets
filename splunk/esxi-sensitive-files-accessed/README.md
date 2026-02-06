# ESXi Sensitive Files Accessed

**Type:** TTP

**Author:** Raven Tait, Splunk

## Description

This detection identifies access to sensitive system and configuration files on an ESXi host, including authentication data, service configurations, and VMware-specific management settings. Interaction with these files may indicate adversary reconnaissance, credential harvesting, or preparation for privilege escalation, lateral movement, or persistence.

## MITRE ATT&CK

- T1003.008
- T1005

## Analytic Stories

- ESXi Post Compromise
- Black Basta Ransomware
- China-Nexus Threat Activity

## Data Sources

- VMWare ESXi Syslog

## Sample Data

- **Source:** vmware:esxlog
  **Sourcetype:** vmw-syslog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.008/esxi_sensitive_files/esxi_sensitive_files.log


---

*Source: [Splunk Security Content](detections/application/esxi_sensitive_files_accessed.yml)*
