# Windows Special Privileged Logon On Multiple Hosts

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects a user authenticating with special privileges on 30 or more remote endpoints within a 5-minute window. It leverages Event ID 4672 from Windows Security logs to identify this behavior. This activity is significant as it may indicate lateral movement or remote code execution by an adversary. If confirmed malicious, the attacker could gain extensive control over the network, potentially leading to privilege escalation, data exfiltration, or further compromise of the environment. Security teams should adjust detection thresholds based on their specific environment.

## MITRE ATT&CK

- T1087
- T1021.002
- T1135

## Analytic Stories

- Active Directory Privilege Escalation
- Active Directory Lateral Movement
- Compromised Windows Host

## Data Sources

- Windows Event Log Security 4672

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078/special_logon_on_mulitple_hosts/windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_special_privileged_logon_on_multiple_hosts.yml)*
