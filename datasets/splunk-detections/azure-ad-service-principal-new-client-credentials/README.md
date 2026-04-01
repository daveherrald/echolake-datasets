# Azure AD Service Principal New Client Credentials

**Type:** TTP

**Author:** Mauricio Velazco, Gowthamaraj Rajendran, Splunk

## Description

This dataset contains sample data for detecting the addition of new credentials to Service Principals and Applications in Azure AD. It leverages Azure AD AuditLogs, specifically monitoring the "Update application*Certificates and secrets management" operation. This activity is significant as it may indicate an adversary attempting to maintain persistent access or escalate privileges within the Azure environment. If confirmed malicious, attackers could use these new credentials to log in as the service principal, potentially compromising sensitive accounts and resources, leading to unauthorized access and control over the Azure environment.

## MITRE ATT&CK

- T1098.001

## Analytic Stories

- Azure Active Directory Persistence
- Azure Active Directory Privilege Escalation
- NOBELIUM Group
- Scattered Lapsus$ Hunters

## Data Sources

- Azure Active Directory

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.001/azure_ad_service_principal_credentials/azure-audit.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_service_principal_new_client_credentials.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
