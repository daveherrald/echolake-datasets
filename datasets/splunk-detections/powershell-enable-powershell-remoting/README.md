# PowerShell Enable PowerShell Remoting

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the use of the Enable-PSRemoting cmdlet, which allows PowerShell remoting on a local or remote computer. This detection leverages PowerShell Script Block Logging (EventCode 4104) to identify when this cmdlet is executed. Monitoring this activity is crucial as it can indicate an attacker enabling remote command execution capabilities on a compromised system. If confirmed malicious, this activity could allow an attacker to take control of the system remotely, execute commands, and potentially pivot to other systems within the network, leading to further compromise and lateral movement.

## MITRE ATT&CK

- T1059.001

## Analytic Stories

- Malicious PowerShell

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/atomic_red_team/4104-psremoting-windows-powershell.log


---

*Source: [Splunk Security Content](detections/endpoint/powershell_enable_powershell_remoting.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
