# Cisco ASA - AAA Policy Tampering

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This analytic detects modifications to authentication and authorization (AAA) security policies on Cisco ASA devices via CLI or ASDM.
AAA policies control critical security mechanisms including authentication attempts, lockout thresholds, password policies, and access control settings that protect administrative access to network infrastructure.
Adversaries or malicious insiders may weaken authentication policies to facilitate brute force attacks, disable account lockouts to enable unlimited password attempts, reduce password complexity requirements, or modify authorization settings to elevate privileges and maintain persistent access.
The detection monitors for command execution events containing AAA-related commands such as `aaa authentication`, `aaa authorization`, or `aaa local authentication`, focusing on changes to authentication attempts, lockout policies, and access control configurations.
Investigate any unauthorized modifications to AAA policies, especially changes that weaken security posture (increasing max-fail attempts, disabling lockouts, reducing password requirements), and verify these changes against approved change management processes and security policies.


## MITRE ATT&CK

- T1556.004

## Analytic Stories

- Suspicious Cisco Adaptive Security Appliance Activity

## Data Sources

- Cisco ASA Logs

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:asa
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_asa/generic/cisco_asa_generic_logs.log


---

*Source: [Splunk Security Content](detections/application/cisco_asa___aaa_policy_tampering.yml)*
