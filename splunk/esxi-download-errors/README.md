# ESXi Download Errors

**Type:** Anomaly

**Author:** Raven Tait, Splunk

## Description

This detection identifies failed file download attempts on ESXi hosts by looking for specific error messages in the system logs. These failures may indicate unauthorized or malicious attempts to install or update components—such as VIBs or scripts

## MITRE ATT&CK

- T1601.001
- T1562.001

## Analytic Stories

- ESXi Post Compromise
- Black Basta Ransomware

## Data Sources

- VMWare ESXi Syslog

## Sample Data

- **Source:** vmware:esxlog
  **Sourcetype:** vmw-syslog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1601.001/esxi_download_errors/esxi_download_errors.log


---

*Source: [Splunk Security Content](detections/application/esxi_download_errors.yml)*
