# Windows Attempt To Stop Security Service

**Type:** TTP

**Author:** Rico Valdez, Nasreddine Bencherchali, Splunk

## Description

This dataset contains sample data for detecting attempts to stop security-related services on an endpoint, which may indicate malicious activity. It leverages data from Endpoint Detection and Response (EDR) agents, specifically searching for processes involving the "sc.exe" or "net.exe" command with the "stop" parameter or the PowerShell "Stop-Service" cmdlet. This activity is significant because disabling security services can undermine the organization's security posture, potentially leading to unauthorized access, data exfiltration, or further attacks like malware installation or privilege escalation. If confirmed malicious, this behavior could compromise the endpoint and the entire network, necessitating immediate investigation and response.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- WhisperGate
- Graceful Wipe Out Attack
- Disabling Security Tools
- Data Destruction
- Azorult
- Trickbot

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/win_defend_service_stop/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_attempt_to_stop_security_service.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
