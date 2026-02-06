# Cisco Duo Policy Allow Devices Without Screen Lock

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic detects when a Duo policy is created or updated to allow devices without a screen lock requirement. It identifies this behavior 
by searching Duo administrator activity logs for policy creation or update events where the 'require_lock' setting is set to false. This action may indicate 
a weakening of device security controls, potentially exposing the organization to unauthorized access if devices are lost or stolen. For a Security Operations 
Center (SOC), identifying such policy changes is critical, as attackers or malicious insiders may attempt to lower authentication standards to facilitate 
unauthorized access. The impact of this attack could include increased risk of credential compromise, data breaches, or lateral movement within the 
environment due to reduced device security requirements.


## MITRE ATT&CK

- T1556

## Analytic Stories

- Cisco Duo Suspicious Activity

## Data Sources

- Cisco Duo Administrator

## Sample Data

- **Source:** duo
  **Sourcetype:** cisco:duo:administrator
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1556/cisco_duo_policy_allow_devices_without_screen_lock/cisco_duo_administrator.json


---

*Source: [Splunk Security Content](detections/application/cisco_duo_policy_allow_devices_without_screen_lock.yml)*
