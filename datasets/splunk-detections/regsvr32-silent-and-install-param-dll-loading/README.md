# Regsvr32 Silent and Install Param Dll Loading

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the loading of a DLL using the regsvr32 application with the silent parameter and DLLInstall execution. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process command-line arguments and parent process details. This activity is significant as it is commonly used by RAT malware like Remcos and njRAT to load malicious DLLs on compromised machines. If confirmed malicious, this technique could allow attackers to execute arbitrary code, maintain persistence, and further compromise the system.

## MITRE ATT&CK

- T1218.010

## Analytic Stories

- AsyncRAT
- Hermetic Wiper
- Living Off The Land
- Data Destruction
- Remcos
- Suspicious Regsvr32 Activity

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.005/vbs_wscript/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/regsvr32_silent_and_install_param_dll_loading.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
