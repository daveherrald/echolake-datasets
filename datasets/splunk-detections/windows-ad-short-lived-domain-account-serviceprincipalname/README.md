# Windows AD Short Lived Domain Account ServicePrincipalName

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying the addition and quick deletion of a Service Principal Name (SPN) to a domain account within 5 minutes. This detection leverages EventCode 5136 from the Windows Security Event Log, focusing on changes to the servicePrincipalName attribute. This activity is significant as it may indicate an attempt to perform Kerberoasting, a technique used to crack the cleartext password of a domain account offline. If confirmed malicious, this could allow an attacker to gain unauthorized access to sensitive information or escalate privileges within the domain environment.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/short_lived_service_principal_name/windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_ad_short_lived_domain_account_serviceprincipalname.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
