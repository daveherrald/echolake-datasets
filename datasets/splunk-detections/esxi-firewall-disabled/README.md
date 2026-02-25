# ESXi Firewall Disabled

**Type:** TTP

**Author:** Raven Tait, Splunk

## Description

This detection identifies when the ESXi firewall is disabled or set to permissive mode, which can expose the host to unauthorized access and network-based attacks. Such changes are often a precursor to lateral movement, data exfiltration, or the installation of malicious software by a threat actor.

## MITRE ATT&CK

- T1562.004

## Analytic Stories

- ESXi Post Compromise
- Black Basta Ransomware
- China-Nexus Threat Activity

## Data Sources

- VMWare ESXi Syslog

## Sample Data

- **Source:** vmware:esxlog
  **Sourcetype:** vmw-syslog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.004/esxi_firewall_disabled/esxi_firewall_disabled.log


---

*Source: [Splunk Security Content](detections/application/esxi_firewall_disabled.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
