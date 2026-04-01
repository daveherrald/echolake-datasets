# ESXi System Information Discovery

**Type:** TTP

**Author:** Raven Tait, Splunk

## Description

This detection identifies the use of ESXCLI system-level commands that retrieve configuration details. While used for legitimate administration, this behavior may also indicate adversary reconnaissance aimed at profiling the ESXi host's capabilities, build information, or system role in preparation for further compromise.

## MITRE ATT&CK

- T1082

## Analytic Stories

- ESXi Post Compromise
- Black Basta Ransomware

## Data Sources

- VMWare ESXi Syslog

## Sample Data

- **Source:** vmware:esxlog
  **Sourcetype:** vmw-syslog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1082/esxi_system_information/esxi_system_information.log


---

*Source: [Splunk Security Content](detections/application/esxi_system_information_discovery.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
