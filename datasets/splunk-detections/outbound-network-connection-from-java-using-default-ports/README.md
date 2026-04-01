# Outbound Network Connection from Java Using Default Ports

**Type:** TTP

**Author:** Mauricio Velazco, Lou Stella, Splunk

## Description

This dataset contains sample data for detecting outbound network connections from Java processes to default ports used by LDAP and RMI protocols, which may indicate exploitation of the CVE-2021-44228-Log4j vulnerability. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process and network traffic logs. Monitoring this activity is crucial as it can signify an attacker’s attempt to perform JNDI lookups and retrieve malicious payloads. If confirmed malicious, this activity could lead to remote code execution and further compromise of the affected server.

## MITRE ATT&CK

- T1190
- T1133

## Analytic Stories

- Log4Shell CVE-2021-44228

## Data Sources

- Sysmon EventID 1 AND Sysmon EventID 3

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/outbound_java/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/outbound_network_connection_from_java_using_default_ports.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
