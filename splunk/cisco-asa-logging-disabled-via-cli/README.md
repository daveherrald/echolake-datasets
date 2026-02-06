# Cisco ASA - Logging Disabled via CLI

**Type:** TTP

**Author:** Bhavin Patel, Micheal Haag, Nasreddine Bencherchali, Splunk

## Description

This analytic detects the disabling of logging functionality on a Cisco ASA device
through CLI commands. Adversaries or malicious insiders may attempt to disable logging
to evade detection and hide malicious activity. The detection looks for specific ASA
syslog message IDs (111010, 111008) associated with command execution,
combined with suspicious commands such as `no logging`, `logging disable`,
`clear logging`, or `no logging host`. Disabling logging on a firewall or security device
is a strong indicator of defense evasion.


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

*Source: [Splunk Security Content](detections/application/cisco_asa___logging_disabled_via_cli.yml)*
