# Azure AD Service Principal New Client Credentials

**Type:** TTP

**Author:** Mauricio Velazco, Gowthamaraj Rajendran, Splunk

## Description

The following analytic detects the addition of new credentials to Service Principals and Applications in Azure AD. It leverages Azure AD AuditLogs, specifically monitoring the "Update application*Certificates and secrets management" operation. This activity is significant as it may indicate an adversary attempting to maintain persistent access or escalate privileges within the Azure environment. If confirmed malicious, attackers could use these new credentials to log in as the service principal, potentially compromising sensitive accounts and resources, leading to unauthorized access and control over the Azure environment.

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
