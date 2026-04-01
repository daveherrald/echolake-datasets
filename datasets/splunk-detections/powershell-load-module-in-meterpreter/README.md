# Powershell Load Module in Meterpreter

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the execution of suspicious PowerShell commands associated with Meterpreter modules, such as "MSF.Powershell" and "MSF.Powershell.Meterpreter". It leverages PowerShell Script Block Logging (EventCode=4104) to capture and analyze the full command sent to PowerShell. This activity is significant as it indicates potential post-exploitation actions, including credential dumping and persistence mechanisms. If confirmed malicious, an attacker could gain extensive control over the compromised system, escalate privileges, and maintain long-term access, posing a severe threat to the environment.

## MITRE ATT&CK

- T1059.001

## Analytic Stories

- MetaSploit

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059/metasploit/msf.powershell.powershell.log


---

*Source: [Splunk Security Content](detections/endpoint/powershell_load_module_in_meterpreter.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
