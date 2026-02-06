# Azure AD New Custom Domain Added

**Type:** TTP

**Author:** Mauricio Velazco, Gowthamaraj Rajendran, Splunk

## Description

The following analytic detects the addition of a new custom domain within an Azure Active Directory (AD) tenant. It leverages Azure AD AuditLogs to identify successful "Add unverified domain" operations. This activity is significant as it may indicate an adversary attempting to establish persistence by setting up identity federation backdoors, allowing them to impersonate users and bypass authentication mechanisms. If confirmed malicious, this could enable attackers to gain unauthorized access, escalate privileges, and maintain long-term access to the Azure AD environment, posing a severe security risk.

## MITRE ATT&CK

- T1484.002

## Analytic Stories

- Azure Active Directory Persistence

## Data Sources

- Azure Active Directory Add unverified domain

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1484.002/new_federated_domain/azure-audit.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_new_custom_domain_added.yml)*
