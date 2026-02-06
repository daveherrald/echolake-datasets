# PowerShell - Connect To Internet With Hidden Window

**Type:** Hunting

**Author:** David Dorsey, Michael Haag Splunk

## Description

The following analytic detects PowerShell commands using the WindowStyle parameter to hide the window while connecting to the Internet. This behavior is identified through Endpoint Detection and Response (EDR) telemetry, focusing on command-line executions that include variations of the WindowStyle parameter. This activity is significant because it attempts to bypass default PowerShell execution policies and conceal its actions, which is often indicative of malicious intent. If confirmed malicious, this could allow an attacker to execute commands stealthily, potentially leading to unauthorized data exfiltration or further compromise of the endpoint.

## MITRE ATT&CK

- T1059.001

## Analytic Stories

- AgentTesla
- HAFNIUM Group
- Hermetic Wiper
- Possible Backdoor Activity Associated With MUDCARP Espionage Campaigns
- Malicious PowerShell
- Data Destruction
- Log4Shell CVE-2021-44228

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/hidden_powershell/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/powershell___connect_to_internet_with_hidden_window.yml)*
