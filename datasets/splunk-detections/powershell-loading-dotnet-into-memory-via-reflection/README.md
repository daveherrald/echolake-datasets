# PowerShell Loading DotNET into Memory via Reflection

**Type:** Anomaly

**Author:** Michael Haag, Teoderick Contreras Splunk

## Description

This dataset contains sample data for detecting the use of PowerShell scripts to load .NET assemblies into memory via reflection, a technique often used in malicious activities such as those by Empire and Cobalt Strike. It leverages PowerShell Script Block Logging (EventCode=4104) to capture and analyze the full command executed. This behavior is significant as it can indicate advanced attack techniques aiming to execute code in memory, bypassing traditional defenses. If confirmed malicious, this activity could lead to unauthorized code execution, privilege escalation, and persistent access within the environment.

## MITRE ATT&CK

- T1059.001

## Analytic Stories

- Winter Vivern
- AgentTesla
- AsyncRAT
- Hermetic Wiper
- Malicious PowerShell
- Data Destruction
- 0bj3ctivity Stealer
- Hellcat Ransomware

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/reflection.log


---

*Source: [Splunk Security Content](detections/endpoint/powershell_loading_dotnet_into_memory_via_reflection.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
