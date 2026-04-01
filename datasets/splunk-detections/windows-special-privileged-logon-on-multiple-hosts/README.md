# Windows Special Privileged Logon On Multiple Hosts

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting a user authenticating with special privileges on 30 or more remote endpoints within a 5-minute window. It leverages Event ID 4672 from Windows Security logs to identify this behavior. This activity is significant as it may indicate lateral movement or remote code execution by an adversary. If confirmed malicious, the attacker could gain extensive control over the network, potentially leading to privilege escalation, data exfiltration, or further compromise of the environment. Security teams should adjust detection thresholds based on their specific environment.

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


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
