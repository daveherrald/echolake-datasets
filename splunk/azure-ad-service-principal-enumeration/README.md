# Azure AD Service Principal Enumeration

**Type:** TTP

**Author:** Dean Luxton

## Description

This detection leverages azure graph activity logs to identify when graph APIs have been used to identify 10 or more service principals. This type of behaviour is associated with tools such as Azure enumberation tools such as AzureHound or ROADtools.

## MITRE ATT&CK

- T1087.004
- T1526

## Analytic Stories

- Azure Active Directory Privilege Escalation
- Compromised User Account

## Data Sources

- Azure Active Directory MicrosoftGraphActivityLogs

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.004/azurehound/azurehound.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_service_principal_enumeration.yml)*
