# ESXi Bulk VM Termination

**Type:** TTP

**Author:** Raven Tait, Splunk

## Description

This detection identifies when all virtual machines on an ESXi host are abruptly terminated, which may indicate malicious activity such as a deliberate denial-of-service, ransomware staging, or an attempt to destroy critical workloads.

## MITRE ATT&CK

- T1673
- T1529
- T1499

## Analytic Stories

- ESXi Post Compromise
- Black Basta Ransomware

## Data Sources

- VMWare ESXi Syslog

## Sample Data

- **Source:** vmware:esxlog
  **Sourcetype:** vmw-syslog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1529/esxi_bulk_vm_termination/esxi_bulk_vm_termination.log


---

*Source: [Splunk Security Content](detections/application/esxi_bulk_vm_termination.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
