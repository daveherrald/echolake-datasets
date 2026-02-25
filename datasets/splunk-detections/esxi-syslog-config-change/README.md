# ESXi Syslog Config Change

**Type:** TTP

**Author:** Raven Tait, Splunk

## Description

This detection identifies changes to the syslog configuration on an ESXi host using esxcli, which may indicate an attempt to disrupt log collection and evade detection.

## MITRE ATT&CK

- T1562.003

## Analytic Stories

- ESXi Post Compromise
- Black Basta Ransomware

## Data Sources

- VMWare ESXi Syslog

## Sample Data

- **Source:** vmware:esxlog
  **Sourcetype:** vmw-syslog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.003/esxi_syslog_config/esxi_syslog_config.log


---

*Source: [Splunk Security Content](detections/application/esxi_syslog_config_change.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
