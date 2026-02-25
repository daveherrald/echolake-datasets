# Cisco Duo Policy Allow Network Bypass 2FA

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting when a Duo policy is created or updated to allow network-based bypass of two-factor authentication (2FA). 
It identifies this behavior by searching Duo administrator logs for policy creation or update actions where the networks_allow field is present, 
indicating that specific networks have been permitted to bypass 2FA requirements. This is achieved by parsing the event description and 
filtering for relevant policy changes, then aggregating the results by user and administrator details. Detecting this behavior is critical 
for a Security Operations Center (SOC) because allowing network-based 2FA bypass can significantly weaken authentication controls, potentially 
enabling unauthorized access if a trusted network is compromised or misconfigured. Attackers or malicious insiders may exploit this policy 
change to circumvent 2FA protections, increasing the risk of account takeover and lateral movement within the environment. Prompt detection 
enables SOC analysts to investigate and respond to potentially risky policy modifications before they can be leveraged for malicious purposes.


## MITRE ATT&CK

- T1556

## Analytic Stories

- Cisco Duo Suspicious Activity

## Data Sources

- Cisco Duo Administrator

## Sample Data

- **Source:** duo
  **Sourcetype:** cisco:duo:administrator
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1556/cisco_duo_policy_allow_network_bypass_2fa/cisco_duo_administrator.json


---

*Source: [Splunk Security Content](detections/application/cisco_duo_policy_allow_network_bypass_2fa.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
