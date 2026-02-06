# CMD Carry Out String Command Parameter

**Type:** Hunting

**Author:** Teoderick Contreras, Bhavin Patel, Splunk

## Description

The following analytic detects the use of `cmd.exe /c` to execute commands, a technique often employed by adversaries and malware to run batch commands or invoke other shells like PowerShell. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions and process metadata. Monitoring this activity is crucial as it can indicate script-based attacks or unauthorized command execution. If confirmed malicious, this behavior could lead to unauthorized code execution, privilege escalation, or persistence within the environment.

## MITRE ATT&CK

- T1059.003

## Analytic Stories

- StealC Stealer
- PlugX
- Warzone RAT
- Data Destruction
- Winter Vivern
- WhisperGate
- ProxyNotShell
- DarkGate Malware
- Chaos Ransomware
- Hermetic Wiper
- Quasar RAT
- Rhysida Ransomware
- DarkCrystal RAT
- Qakbot
- IcedID
- CISA AA23-347A
- Azorult
- Living Off The Land
- Crypto Stealer
- Malicious Inno Setup Loader
- NjRAT
- AsyncRAT
- RedLine Stealer
- Log4Shell CVE-2021-44228
- Interlock Rat
- 0bj3ctivity Stealer

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/cmd_carry_str_param/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/cmd_carry_out_string_command_parameter.yml)*
