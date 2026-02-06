# Cisco Duo Policy Allow Tampered Devices

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic detects when a Duo policy is created or updated to allow tampered or rooted devices, such as jailbroken smartphones, 
to access protected resources. It identifies this behavior by searching Duo administrator activity logs for policy changes where the allow_rooted_devices 
setting is enabled. This is accomplished by filtering for policy creation or update actions and parsing the policy description for the relevant configuration. 
Allowing tampered devices poses a significant security risk, as these devices may bypass built-in security controls, run unauthorized software, or be more 
susceptible to compromise. For a Security Operations Center (SOC), identifying such policy changes is critical because it may indicate either a 
misconfiguration or a malicious attempt to weaken authentication requirements, potentially enabling attackers to access sensitive systems with 
compromised devices. The impact of this attack can include unauthorized access, data breaches, and lateral movement within the environment, 
making prompt detection and response essential to maintaining organizational security.


## MITRE ATT&CK

- T1556

## Analytic Stories

- Cisco Duo Suspicious Activity

## Data Sources

- Cisco Duo Administrator

## Sample Data

- **Source:** duo
  **Sourcetype:** cisco:duo:administrator
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1556/cisco_duo_policy_allow_tampered_devices/cisco_duo_administrator.json


---

*Source: [Splunk Security Content](detections/application/cisco_duo_policy_allow_tampered_devices.yml)*
