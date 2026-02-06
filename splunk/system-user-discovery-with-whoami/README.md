# System User Discovery With Whoami

**Type:** Anomaly

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects the execution of `whoami.exe` without any arguments. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs. This activity is significant because both Red Teams and adversaries use `whoami.exe` to identify the current logged-in user, aiding in situational awareness and Active Directory discovery. If confirmed malicious, this behavior could indicate an attacker is gathering information to further compromise the system, potentially leading to privilege escalation or lateral movement within the network.

## MITRE ATT&CK

- T1033

## Analytic Stories

- Winter Vivern
- Active Directory Discovery
- Rhysida Ransomware
- Qakbot
- CISA AA23-347A
- PHP-CGI RCE Attack on Japanese Organizations
- LAMEHUG

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1033/AD_discovery/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/system_user_discovery_with_whoami.yml)*
