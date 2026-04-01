# ESXi VIB Acceptance Level Tampering

**Type:** TTP

**Author:** Raven Tait, Splunk

## Description

This detection identifies changes to the VIB (vSphere Installation Bundle) acceptance level on an ESXi host. Modifying the acceptance level, such as setting it to CommunitySupported, lowers the system's integrity enforcement and may allow the installation of unsigned or unverified software.

## MITRE ATT&CK

- T1562

## Analytic Stories

- ESXi Post Compromise
- Black Basta Ransomware
- China-Nexus Threat Activity

## Data Sources

- VMWare ESXi Syslog

## Sample Data

- **Source:** vmware:esxlog
  **Sourcetype:** vmw-syslog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562/esxi_vib_acceptance_level_tampering/esxi_vib_acceptance_level_tampering.log


---

*Source: [Splunk Security Content](detections/application/esxi_vib_acceptance_level_tampering.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
