# Cisco Configuration Archive Logging Analysis

**Type:** Hunting

**Author:** Bhavin Patel, Michael Haag, Splunk

## Description

This analytic provides comprehensive monitoring of configuration changes on Cisco devices by analyzing archive logs. Configuration archive logging captures all changes made to a device's configuration, providing a detailed audit trail that can be used to identify suspicious or malicious activities. This detection is particularly valuable for identifying patterns of malicious configuration changes that might indicate an attacker's presence, such as the creation of backdoor accounts, SNMP community string modifications, and TFTP server configurations for data exfiltration. By analyzing these logs, security teams can gain a holistic view of configuration changes across sessions and users, helping to detect sophisticated attack campaigns like those conducted by threat actors such as Static Tundra.

## MITRE ATT&CK

- T1562.001
- T1098
- T1505.003

## Analytic Stories

- Cisco Smart Install Remote Code Execution CVE-2018-0171

## Data Sources

- Cisco IOS Logs

## Sample Data

- **Source:** cisco:ios
  **Sourcetype:** cisco:ios
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/cisco/cisco_smart_install/cisco_ios.log


---

*Source: [Splunk Security Content](detections/network/cisco_configuration_archive_logging_analysis.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
