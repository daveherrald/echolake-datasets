# ESXi Reverse Shell Patterns

**Type:** TTP

**Author:** Raven Tait, Splunk

## Description

This detection looks for reverse shell string patterns on an ESXi host, which may indicate that a threat actor is attempting to establish remote control over the system.

## MITRE ATT&CK

- T1059

## Analytic Stories

- ESXi Post Compromise
- Black Basta Ransomware

## Data Sources

- VMWare ESXi Syslog

## Sample Data

- **Source:** vmware:esxlog
  **Sourcetype:** vmw-syslog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059/esxi_reverse_shell/esxi_reverse_shell.log


---

*Source: [Splunk Security Content](detections/application/esxi_reverse_shell_patterns.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
