# Cisco Network Interface Modifications

**Type:** Anomaly

**Author:** Bhavin Patel, Michael Haag, Splunk

## Description

This analytic detects the creation or modification of network interfaces on Cisco devices, which could indicate an attacker establishing persistence or preparing for lateral movement. After gaining initial access to network devices, threat actors like Static Tundra often create new interfaces (particularly loopback interfaces) to establish covert communication channels or maintain persistence. This detection specifically looks for the configuration of new interfaces, interface state changes, and the assignment of IP addresses to interfaces. These activities are particularly concerning when they involve unusual interface names or descriptions containing suspicious terms.

## MITRE ATT&CK

- T1556
- T1021
- T1133

## Analytic Stories

- Cisco Smart Install Remote Code Execution CVE-2018-0171

## Data Sources

- Cisco IOS Logs

## Sample Data

- **Source:** cisco:ios
  **Sourcetype:** cisco:ios
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/cisco/cisco_smart_install/cisco_ios.log


---

*Source: [Splunk Security Content](detections/network/cisco_network_interface_modifications.yml)*
