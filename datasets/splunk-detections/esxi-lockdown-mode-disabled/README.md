# ESXi Lockdown Mode Disabled

**Type:** TTP

**Author:** Raven Tait, Splunk

## Description

This detection identifies when Lockdown Mode is disabled on an ESXi host, which can indicate that a threat actor is attempting to weaken host security controls. Disabling Lockdown Mode allows broader remote access via SSH or the host client and may precede further malicious actions such as data exfiltration, lateral movement, or VM tampering.

## MITRE ATT&CK

- T1562

## Analytic Stories

- ESXi Post Compromise
- Black Basta Ransomware

## Data Sources

- VMWare ESXi Syslog

## Sample Data

- **Source:** vmware:esxlog
  **Sourcetype:** vmw-syslog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562/esxi_lockdown_disabled/esxi_lockdown_disabled.log


---

*Source: [Splunk Security Content](detections/application/esxi_lockdown_mode_disabled.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
