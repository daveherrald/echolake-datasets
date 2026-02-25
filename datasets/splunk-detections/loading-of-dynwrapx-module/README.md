# Loading Of Dynwrapx Module

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the loading of the dynwrapx.dll module, which is associated with the DynamicWrapperX ActiveX component. This detection leverages Sysmon EventCode 7 to identify processes that load or register dynwrapx.dll. This activity is significant because DynamicWrapperX can be used to call Windows API functions in scripts, making it a potential tool for malicious actions. If confirmed malicious, this could allow an attacker to execute arbitrary code, escalate privileges, or maintain persistence on the host. Immediate investigation of parallel processes and registry modifications is recommended.

## MITRE ATT&CK

- T1055.001

## Analytic Stories

- Remcos
- AsyncRAT

## Data Sources

- Sysmon EventID 7

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/remcos/remcos_dynwrapx/sysmon_dynwraper.log


---

*Source: [Splunk Security Content](detections/endpoint/loading_of_dynwrapx_module.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
