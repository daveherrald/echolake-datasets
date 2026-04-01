# ESXi VM Exported via Remote Tool

**Type:** TTP

**Author:** Raven Tait, Splunk

## Description

This detection identifies the use of a remote tool to download virtual machine disk files from a datastore. The NFC protocol is used by management tools to transfer files to and from ESXi hosts, but it can also be abused by attackers or insiders to exfiltrate full virtual disk images

## MITRE ATT&CK

- T1005

## Analytic Stories

- ESXi Post Compromise
- Black Basta Ransomware

## Data Sources

- VMWare ESXi Syslog

## Sample Data

- **Source:** vmware:esxlog
  **Sourcetype:** vmw-syslog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1005/esxi_vm_download/esxi_vm_download.log


---

*Source: [Splunk Security Content](detections/application/esxi_vm_exported_via_remote_tool.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
