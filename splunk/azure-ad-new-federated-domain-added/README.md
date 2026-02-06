# Azure AD New Federated Domain Added

**Type:** TTP

**Author:** Mauricio Velazco, Gowthamaraj Rajendran, Splunk

## Description

The following analytic detects the addition of a new federated domain within an Azure Active Directory tenant. It leverages Azure AD AuditLogs to identify successful "Set domain authentication" operations. This activity is significant as it may indicate the use of the Azure AD identity federation backdoor technique, allowing an adversary to establish persistence. If confirmed malicious, the attacker could impersonate any user, bypassing password and MFA requirements, potentially leading to unauthorized access and control over the Azure AD environment.

## MITRE ATT&CK

- T1484.002

## Analytic Stories

- Azure Active Directory Persistence
- Scattered Lapsus$ Hunters
- Hellcat Ransomware
- Storm-0501 Ransomware

## Data Sources

- Azure Active Directory Set domain authentication

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1484.002/new_federated_domain/azure-audit.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_new_federated_domain_added.yml)*
