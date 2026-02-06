# Cisco ASA - Logging Filters Configuration Tampering

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This analytic detects tampering with logging filter configurations on Cisco ASA devices via CLI or ASDM.
Adversaries may reduce logging levels or disable specific log categories to evade detection, hide their activities, or prevent security monitoring systems from capturing evidence of their actions. By lowering logging verbosity, attackers can operate with reduced visibility to security teams.
The detection monitors for logging configuration commands (message ID 111008 or 111010) that modify logging destinations (asdm, console, history, mail, monitor, trap) without setting them to higher severity levels (5-notifications, 6-informational, 7-debugging), which may indicate an attempt to reduce logging verbosity.
Investigate unauthorized logging configuration changes that reduce verbosity, especially changes performed by non-administrative accounts, during unusual hours, or without corresponding change management approval.


## MITRE ATT&CK

- T1562

## Analytic Stories

- Suspicious Cisco Adaptive Security Appliance Activity

## Data Sources

- Cisco ASA Logs

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:asa
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_asa/generic/cisco_asa_generic_logs.log


---

*Source: [Splunk Security Content](detections/application/cisco_asa___logging_filters_configuration_tampering.yml)*
