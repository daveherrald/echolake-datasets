# ESXi User Granted Admin Role

**Type:** TTP

**Author:** Raven Tait, Splunk

## Description

This detection identifies when a user is granted the Administrator role on an ESXi host. Assigning elevated privileges is a critical action that can indicate potential malicious behavior if performed unexpectedly. Adversaries who gain access may use this to escalate privileges, maintain persistence, or disable security controls.

## MITRE ATT&CK

- T1098
- T1078

## Analytic Stories

- ESXi Post Compromise
- Black Basta Ransomware

## Data Sources

- VMWare ESXi Syslog

## Sample Data

- **Source:** vmware:esxlog
  **Sourcetype:** vmw-syslog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/esxi_admin_role/esxi_admin_role.log


---

*Source: [Splunk Security Content](detections/application/esxi_user_granted_admin_role.yml)*
