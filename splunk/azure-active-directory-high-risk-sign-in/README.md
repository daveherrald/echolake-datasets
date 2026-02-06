# Azure Active Directory High Risk Sign-in

**Type:** TTP

**Author:** Mauricio Velazco, Gowthamaraj Rajendran, Splunk

## Description

The following analytic detects high-risk sign-in attempts against Azure Active Directory, identified by Azure Identity Protection. It leverages the RiskyUsers and UserRiskEvents log categories from Azure AD events ingested via EventHub. This activity is significant as it indicates potentially compromised accounts, flagged by heuristics and machine learning. If confirmed malicious, attackers could gain unauthorized access to sensitive resources, leading to data breaches or further exploitation within the environment.

## MITRE ATT&CK

- T1110.003
- T1586.003

## Analytic Stories

- Azure Active Directory Account Takeover

## Data Sources

- Azure Active Directory

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/azuread_highrisk/azure-audit.log


---

*Source: [Splunk Security Content](detections/cloud/azure_active_directory_high_risk_sign_in.yml)*
