# Cisco ASA - User Account Lockout Threshold Exceeded

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This analytic detects user account lockouts on Cisco ASA devices resulting from excessive failed authentication attempts.
Account lockouts may indicate brute force attacks, password spraying campaigns, credential stuffing attempts using compromised credentials from external breaches, or misconfigured automation attempting authentication with incorrect credentials. These activities represent attempts to gain unauthorized access to network infrastructure.
The detection monitors for ASA message ID 113006, which is generated when a user account is locked out after exceeding the configured maximum number of failed authentication attempts, capturing the locked account name and the failure threshold that was exceeded.
Investigate account lockouts for privileged or administrative accounts, multiple simultaneous lockouts affecting different accounts (suggesting password spraying), lockouts originating from unusual source IP addresses, lockouts during off-hours, or patterns suggesting automated attack tools.


## MITRE ATT&CK

- T1110.001
- T1110.003

## Analytic Stories

- Suspicious Cisco Adaptive Security Appliance Activity

## Data Sources

- Cisco ASA Logs

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:asa
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_asa/generic/cisco_asa_generic_logs.log


---

*Source: [Splunk Security Content](detections/application/cisco_asa___user_account_lockout_threshold_exceeded.yml)*
