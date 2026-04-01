# Windows Protocol Tunneling with Plink

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This analytic detects the use of Plink (including renamed versions like pvhost.exe) for protocol tunneling, which may be used for egress or lateral movement within an organization. It identifies specific command-line options (-R, -L, -D, -l, -N, -P, -pw) commonly used for port forwarding and tunneling by analyzing process execution logs from Endpoint Detection and Response (EDR) agents. This activity is significant as it may indicate an attempt to bypass network security controls or establish unauthorized connections. If confirmed malicious, this could allow an attacker to exfiltrate data, move laterally across the network, or maintain persistent access, posing a severe threat to the organization's security. The detection covers both the original Plink executable and potential renamed versions, enhancing its ability to catch evasion attempts.

## MITRE ATT&CK

- T1572
- T1021.004

## Analytic Stories

- CISA AA22-257A

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1572/plink/plink-windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_protocol_tunneling_with_plink.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
