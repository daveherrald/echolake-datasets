# Kerberos User Enumeration

**Type:** Anomaly

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting an unusual number of Kerberos Ticket Granting Ticket (TGT) requests for non-existing users from a single source endpoint. It leverages Event ID 4768 and identifies anomalies using the 3-sigma statistical rule. This behavior is significant as it may indicate an adversary performing a user enumeration attack against Active Directory. If confirmed malicious, the attacker could validate a list of usernames, potentially leading to further attacks such as brute force or credential stuffing, compromising the security of the environment.

## MITRE ATT&CK

- T1589.002

## Analytic Stories

- Active Directory Kerberos Attacks

## Data Sources

- Windows Event Log Security 4768

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1589.002/kerberos_user_enumeration/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/kerberos_user_enumeration.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
