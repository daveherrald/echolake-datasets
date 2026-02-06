# Azure AD Service Principal Created

**Type:** TTP

**Author:** Gowthamaraj Rajendran, Mauricio Velazco, Splunk

## Description

The following analytic detects the creation of a Service Principal in an Azure AD environment. It leverages Azure Active Directory events ingested through EventHub, specifically monitoring the "Add service principal" operation. This activity is significant because Service Principals can be used by adversaries to establish persistence and bypass multi-factor authentication and conditional access policies. If confirmed malicious, this could allow attackers to maintain single-factor access to the Azure AD environment, potentially leading to unauthorized access to resources and prolonged undetected activity.

## MITRE ATT&CK

- T1136.003

## Analytic Stories

- Azure Active Directory Persistence
- NOBELIUM Group

## Data Sources

- Azure Active Directory Add service principal

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.003/azure_ad_add_service_principal/azure-audit.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_service_principal_created.yml)*
