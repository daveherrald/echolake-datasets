# PetitPotam Suspicious Kerberos TGT Request

**Type:** TTP

**Author:** Michael Haag, Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting a suspicious Kerberos Ticket Granting Ticket (TGT) request, identified by Event Code 4768. This detection leverages Windows Security Event Logs to identify TGT requests with unusual fields, which may indicate the use of tools like Rubeus following the exploitation of CVE-2021-36942 (PetitPotam). This activity is significant as it can signal an attacker leveraging a compromised certificate to request Kerberos tickets, potentially leading to unauthorized access. If confirmed malicious, this could allow attackers to escalate privileges and persist within the environment, posing a severe security risk.

## MITRE ATT&CK

- T1003

## Analytic Stories

- PetitPotam NTLM Relay on Active Directory Certificate Services
- Active Directory Kerberos Attacks

## Data Sources

- Windows Event Log Security 4768

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1187/petitpotam/windows-xml-1.log


---

*Source: [Splunk Security Content](detections/endpoint/petitpotam_suspicious_kerberos_tgt_request.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
