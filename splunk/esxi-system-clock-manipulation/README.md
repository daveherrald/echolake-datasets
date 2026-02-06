# ESXi System Clock Manipulation

**Type:** TTP

**Author:** Raven Tait, Splunk

## Description

This detection identifies a significant change to the system clock on an ESXi host, which may indicate an attempt to manipulate timestamps and evade detection or forensic analysis

## MITRE ATT&CK

- T1070.006

## Analytic Stories

- ESXi Post Compromise
- Black Basta Ransomware

## Data Sources

- VMWare ESXi Syslog

## Sample Data

- **Source:** vmware:esxlog
  **Sourcetype:** vmw-syslog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070/esxi_system_clock_manipulation/esxi_system_clock_manipulation.log


---

*Source: [Splunk Security Content](detections/application/esxi_system_clock_manipulation.yml)*
