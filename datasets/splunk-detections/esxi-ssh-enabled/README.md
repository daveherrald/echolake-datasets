# ESXi SSH Enabled

**Type:** TTP

**Author:** Raven Tait, Splunk

## Description

This detection identifies SSH being enabled on ESXi hosts, which can be an early indicator of malicious activity. Threat actors often use SSH to gain persistent remote access after compromising credentials or exploiting vulnerabilities.

## MITRE ATT&CK

- T1021.004

## Analytic Stories

- ESXi Post Compromise
- Black Basta Ransomware
- Hellcat Ransomware

## Data Sources

- VMWare ESXi Syslog

## Sample Data

- **Source:** vmware:esxlog
  **Sourcetype:** vmw-syslog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.004/esxi_ssh_enabled/esxi_ssh_enabled.log


---

*Source: [Splunk Security Content](detections/application/esxi_ssh_enabled.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
