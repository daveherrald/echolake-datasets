# Cisco ASA - Packet Capture Activity

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This analytic detects execution of packet capture commands on Cisco ASA devices via CLI or ASDM.
Adversaries may abuse the built-in packet capture functionality to perform network sniffing, intercept credentials transmitted over the network, capture sensitive data in transit, or gather intelligence about network traffic patterns and internal communications. Packet captures can reveal usernames, passwords, session tokens, and confidential business data.
The detection monitors for command execution events (message ID 111008 or 111010) containing "capture" commands, which are used to initiate packet capture sessions on specific interfaces or for specific traffic patterns on the ASA device.
Investigate unauthorized packet capture activities, especially captures targeting sensitive interfaces (internal network segments, DMZ), captures configured to capture large volumes of traffic, captures with suspicious filter criteria, captures initiated by non-administrative accounts, or captures during unusual hours.


## MITRE ATT&CK

- T1040
- T1557

## Analytic Stories

- Suspicious Cisco Adaptive Security Appliance Activity
- ArcaneDoor

## Data Sources

- Cisco ASA Logs

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:asa
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_asa/generic/cisco_asa_generic_logs.log


---

*Source: [Splunk Security Content](detections/application/cisco_asa___packet_capture_activity.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
