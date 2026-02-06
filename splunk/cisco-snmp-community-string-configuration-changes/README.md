# Cisco SNMP Community String Configuration Changes

**Type:** Anomaly

**Author:** Bhavin Patel, Michael Haag, Splunk

## Description

This analytic detects changes to SNMP community strings on Cisco devices, which could indicate an attacker establishing persistence or attempting to extract credentials. After gaining initial access to network devices, threat actors like Static Tundra often modify SNMP configurations to enable unauthorized monitoring and data collection. This detection specifically looks for the configuration of SNMP community strings with read-write (rw) or read-only (ro) permissions, as well as the configuration of SNMP hosts that may be used to exfiltrate data. These activities are particularly concerning as they may represent attempts to establish persistent access or extract sensitive information from compromised devices.

## MITRE ATT&CK

- T1562.001
- T1040
- T1552

## Analytic Stories

- Cisco Smart Install Remote Code Execution CVE-2018-0171

## Data Sources

- Cisco IOS Logs

## Sample Data

- **Source:** cisco:ios
  **Sourcetype:** cisco:ios
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/cisco/cisco_smart_install/cisco_ios.log


---

*Source: [Splunk Security Content](detections/network/cisco_snmp_community_string_configuration_changes.yml)*
