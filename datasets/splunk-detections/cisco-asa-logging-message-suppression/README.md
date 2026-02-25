# Cisco ASA - Logging Message Suppression

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This analytic detects suppression of specific logging messages on Cisco ASA devices using the "no logging message" command.
Adversaries may suppress specific log message IDs to selectively disable logging of security-critical events such as authentication failures, configuration changes, or suspicious network activity. This targeted approach allows attackers to evade detection while maintaining normal logging operations that might otherwise alert administrators to complete logging disablement.
The detection monitors for command execution events (message ID 111008 or 111010) containing the "no logging message" command, which is used to suppress specific message IDs from being logged regardless of the configured severity level.
Investigate unauthorized message suppression, especially suppression of security-critical message IDs (authentication, authorization, configuration changes), suppression performed by non-administrative accounts, during unusual hours, or without documented justification.


## MITRE ATT&CK

- T1562.002
- T1070

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

*Source: [Splunk Security Content](detections/application/cisco_asa___logging_message_suppression.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
