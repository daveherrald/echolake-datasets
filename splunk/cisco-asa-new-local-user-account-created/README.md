# Cisco ASA - New Local User Account Created

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This analytic detects creation of new user accounts on Cisco ASA devices via CLI or ASDM.
Adversaries may create unauthorized user accounts to establish persistence, maintain backdoor access, or elevate privileges on network infrastructure devices. These rogue accounts can provide attackers with continued access even after initial compromise vectors are remediated.
The detection monitors for ASA message ID 502101, which is generated whenever a new user account is created on the device, capturing details including the username, privilege level, and the administrator who created the account.
Investigate unexpected account creations, especially those with elevated privileges (level 15), accounts created outside business hours, accounts with suspicious or generic names, or accounts created by non-administrative users.


## MITRE ATT&CK

- T1136.001
- T1078.003

## Analytic Stories

- Suspicious Cisco Adaptive Security Appliance Activity

## Data Sources

- Cisco ASA Logs

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:asa
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_asa/generic/cisco_asa_generic_logs.log


---

*Source: [Splunk Security Content](detections/application/cisco_asa___new_local_user_account_created.yml)*
