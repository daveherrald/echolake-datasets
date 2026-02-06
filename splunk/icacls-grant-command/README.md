# ICACLS Grant Command

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the use of the ICACLS command to grant
additional access permissions to files or directories. It leverages data from Endpoint
Detection and Response (EDR) agents, focusing on specific process names and command-line
arguments. This activity is significant because it is commonly used by Advanced
Persistent Threats (APTs) and coinminer scripts to evade detection and maintain
control over compromised systems. If confirmed malicious, this behavior could allow
attackers to manipulate file permissions, potentially leading to unauthorized access,
data exfiltration, or further system compromise.


## MITRE ATT&CK

- T1222

## Analytic Stories

- Ransomware
- Crypto Stealer
- XMRig
- Defense Evasion or Unauthorized Access Via SDDL Tampering
- NetSupport RMM Tool Abuse

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/icacls_grant_command.yml)*
