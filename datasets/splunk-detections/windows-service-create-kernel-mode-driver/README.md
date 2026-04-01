# Windows Service Create Kernel Mode Driver

**Type:** TTP

**Author:** Michael Haag, Teoderick Contreras Splunk

## Description

This dataset contains sample data for identifying the creation of a new kernel mode driver using the sc.exe command. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs that include command-line details. The activity is significant because adding a kernel driver is uncommon in regular operations and can indicate an attempt to gain low-level access to the system. If confirmed malicious, this could allow an attacker to execute code with high privileges, potentially compromising the entire system and evading traditional security measures.

## MITRE ATT&CK

- T1068
- T1543.003

## Analytic Stories

- Windows Drivers
- CISA AA22-320A

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1068/drivers/sc_kernel.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_service_create_kernel_mode_driver.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
