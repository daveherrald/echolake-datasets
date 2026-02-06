# Cisco ASA - User Account Deleted From Local Database

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This analytic detects deletion of user accounts from Cisco ASA devices via CLI or ASDM.
Adversaries may delete local accounts to cover their tracks, remove evidence of their activities, disrupt incident response efforts, or deny legitimate administrator access during an attack. Account deletion can also indicate an attempt to hide the creation of temporary accounts used during compromise.
The detection monitors for ASA message ID 502102, which is generated whenever a local user account is deleted from the device, capturing details including the deleted username, privilege level, and the administrator who performed the deletion.
Investigate unexpected account deletions, especially those involving privileged accounts (level 15), deletions performed outside business hours, deletions by non-administrative users, or deletions that coincide with other suspicious activities.


## MITRE ATT&CK

- T1531
- T1070.008

## Analytic Stories

- Suspicious Cisco Adaptive Security Appliance Activity

## Data Sources

- Cisco ASA Logs

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:asa
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_asa/generic/cisco_asa_generic_logs.log


---

*Source: [Splunk Security Content](detections/application/cisco_asa___user_account_deleted_from_local_database.yml)*
