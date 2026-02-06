# Cisco Duo Policy Allow Old Flash

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic identifies instances where a Duo administrator creates or updates a policy to allow the use of outdated Flash components, specifically by detecting policy changes with the flash_remediation=no remediation attribute. It leverages Duo activity logs ingested via the Cisco Security Cloud App, searching for policy_update or policy_create actions and parsing the policy description for indicators of weakened security controls. This behavior is significant for a SOC because permitting old Flash increases the attack surface, as Flash is widely known for its security vulnerabilities and is no longer supported. Attackers may exploit such policy changes to bypass security controls, introduce malware, or escalate privileges within the environment. Detecting and responding to these policy modifications helps prevent potential exploitation, reduces organizational risk, and ensures adherence to security best practices. Immediate investigation is recommended to determine if the change was authorized or indicative of malicious activity.

## MITRE ATT&CK

- T1556

## Analytic Stories

- Cisco Duo Suspicious Activity

## Data Sources

- Cisco Duo Administrator

## Sample Data

- **Source:** duo
  **Sourcetype:** cisco:duo:administrator
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1556/cisco_duo_policy_allow_old_flash_and_java/cisco_duo_administrator.json


---

*Source: [Splunk Security Content](detections/application/cisco_duo_policy_allow_old_flash.yml)*
