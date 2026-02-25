# Windows AD ServicePrincipalName Added To Domain Account

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the addition of a Service Principal Name (SPN) to a domain account. It leverages Windows Event Code 5136 and monitors changes to the servicePrincipalName attribute. This activity is significant because it may indicate an attempt to perform Kerberoasting, a technique where attackers extract and crack service account passwords offline. If confirmed malicious, this could allow an attacker to obtain cleartext passwords, leading to unauthorized access and potential lateral movement within the domain environment.

## MITRE ATT&CK

- T1098

## Analytic Stories

- Sneaky Active Directory Persistence Tricks
- Interlock Ransomware

## Data Sources

- Windows Event Log Security 5136

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/service_principal_name_added/windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_ad_serviceprincipalname_added_to_domain_account.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
