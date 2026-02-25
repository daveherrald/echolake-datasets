# Cisco ASA - Reconnaissance Command Activity

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This analytic detects potential reconnaissance activities on Cisco ASA devices by identifying execution of multiple information-gathering "show" commands within a short timeframe.
Adversaries who gain initial access to network infrastructure devices typically perform systematic reconnaissance to understand the device configuration, network topology, security policies, connected systems, and potential attack paths. This reconnaissance phase involves executing multiple "show" commands to enumerate device details, running configurations, active connections, routing information, and VPN sessions.
The detection monitors for command execution events (message ID 111009) containing reconnaissance-oriented "show" commands (such as show running-config, show version, show interface, show crypto, show conn, etc.) and triggers when 7 or more distinct reconnaissance commands are executed within a 5-minute window by the same user.
Investigate reconnaissance bursts from non-administrative accounts, unusual source IP addresses, activity during off-hours, methodical command sequences suggesting automated enumeration, or reconnaissance activity correlated with other suspicious behaviors.
We recommend adapting the detection filters to exclude known legitimate administrative activities.


## MITRE ATT&CK

- T1082
- T1590.001
- T1590.005

## Analytic Stories

- Suspicious Cisco Adaptive Security Appliance Activity

## Data Sources

- Cisco ASA Logs

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:asa
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_asa/generic/cisco_asa_generic_logs.log


---

*Source: [Splunk Security Content](detections/application/cisco_asa___reconnaissance_command_activity.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
