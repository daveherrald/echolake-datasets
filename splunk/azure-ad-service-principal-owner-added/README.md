# Azure AD Service Principal Owner Added

**Type:** TTP

**Author:** Mauricio Velazco, Gowthamaraj Rajendran, Splunk

## Description

The following analytic detects the addition of a new owner to a Service Principal within an Azure AD tenant. It leverages Azure Active Directory events from the AuditLog log category to identify this activity. This behavior is significant because Service Principals do not support multi-factor authentication or conditional access policies, making them a target for adversaries seeking persistence or privilege escalation. If confirmed malicious, this activity could allow attackers to maintain access to the Azure AD environment with single-factor authentication, potentially leading to unauthorized access and control over critical resources.

## MITRE ATT&CK

- T1098

## Analytic Stories

- Azure Active Directory Persistence
- Azure Active Directory Privilege Escalation
- NOBELIUM Group

## Data Sources

- Azure Active Directory Add owner to application

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/azure_ad_add_serviceprincipal_owner/azure-audit.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_service_principal_owner_added.yml)*
