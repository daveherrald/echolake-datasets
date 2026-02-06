# ESXi Shell Access Enabled

**Type:** TTP

**Author:** Raven Tait, Splunk

## Description

This detection identifies when the ESXi Shell is enabled on a host, which may indicate that a malicious actor is preparing to execute commands locally or establish persistent access. Enabling the shell outside of approved maintenance windows can be a sign of compromise or unauthorized administrative activity.

## MITRE ATT&CK

- T1021

## Analytic Stories

- ESXi Post Compromise
- Black Basta Ransomware

## Data Sources

- VMWare ESXi Syslog

## Sample Data

- **Source:** vmware:esxlog
  **Sourcetype:** vmw-syslog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021/esxi_shell_enabled/esxi_shell_enabled.log


---

*Source: [Splunk Security Content](detections/application/esxi_shell_access_enabled.yml)*
