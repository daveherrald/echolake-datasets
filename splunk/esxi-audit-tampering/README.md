# ESXi Audit Tampering

**Type:** TTP

**Author:** Raven Tait, Splunk

## Description

This detection identifies the use of the esxcli system auditrecords commands, which can be used to tamper with logging on an ESXi host. This action may indicate an attempt to evade detection or hinder forensic analysis by preventing the recording of system-level audit events.

## MITRE ATT&CK

- T1562.003
- T1070

## Analytic Stories

- ESXi Post Compromise
- Black Basta Ransomware

## Data Sources

- VMWare ESXi Syslog

## Sample Data

- **Source:** vmware:esxlog
  **Sourcetype:** vmw-syslog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.003/esxi_audit_tampering/esxi_audit_tampering.log


---

*Source: [Splunk Security Content](detections/application/esxi_audit_tampering.yml)*
