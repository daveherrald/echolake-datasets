# PingID New MFA Method After Credential Reset

**Type:** TTP

**Author:** Steven Dick

## Description

This dataset contains sample data for identifying the provisioning of a new MFA device shortly after a password reset. It detects this activity by correlating Windows Event Log events for password changes (EventID 4723, 4724) with PingID logs indicating device pairing. This behavior is significant as it may indicate a social engineering attack where a threat actor impersonates a valid user to reset credentials and add a new MFA device. If confirmed malicious, this activity could allow an attacker to gain persistent access to the compromised account, bypassing traditional security measures.

## MITRE ATT&CK

- T1621
- T1556.006
- T1098.005

## Analytic Stories

- Compromised User Account
- Scattered Lapsus$ Hunters

## Data Sources

- PingID

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1621/pingid/windows_pw_reset.log

- **Source:** PINGID
  **Sourcetype:** _json
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1621/pingid/pingid.log


---

*Source: [Splunk Security Content](detections/application/pingid_new_mfa_method_after_credential_reset.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
