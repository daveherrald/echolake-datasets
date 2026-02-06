# ESXi VM Discovery

**Type:** TTP

**Author:** Raven Tait, Splunk

## Description

This detection identifies the use of ESXCLI commands to discover virtual machines on an ESXi host While used by administrators, this activity may also indicate adversary reconnaissance aimed at identifying high value targets, mapping the virtual environment, or preparing for data theft or destructive operations.

## MITRE ATT&CK

- T1673

## Analytic Stories

- ESXi Post Compromise
- Black Basta Ransomware
- China-Nexus Threat Activity

## Data Sources

- VMWare ESXi Syslog

## Sample Data

- **Source:** vmware:esxlog
  **Sourcetype:** vmw-syslog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1673/esxi_vm_discovery/esxi_vm_discovery.log


---

*Source: [Splunk Security Content](detections/application/esxi_vm_discovery.yml)*
