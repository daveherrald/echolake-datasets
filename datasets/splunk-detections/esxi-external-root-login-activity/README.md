# ESXi External Root Login Activity

**Type:** Anomaly

**Author:** Raven Tait, Splunk

## Description

This detection identifies instances where the ESXi UI is accessed using the root account instead of a delegated administrative user. Direct root access to the UI bypasses role-based access controls and auditing practices, and may indicate risky behavior, misconfiguration, or unauthorized activity by a malicious actor using compromised credentials.

## MITRE ATT&CK

- T1078

## Analytic Stories

- ESXi Post Compromise
- Black Basta Ransomware

## Data Sources

- VMWare ESXi Syslog

## Sample Data

- **Source:** vmware:esxlog
  **Sourcetype:** vmw-syslog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078/esxi_external_root_login/esxi_external_root_login.log


---

*Source: [Splunk Security Content](detections/application/esxi_external_root_login_activity.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
