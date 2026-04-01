# Azure AD Service Principal Authentication

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying authentication events of service principals in Azure Active Directory. It leverages the `azure_monitor_aad` data source, specifically targeting "Sign-in activity" within ServicePrincipalSignInLogs. This detection gathers details such as sign-in frequency, timing, source IPs, and accessed resources. Monitoring these events is significant for SOC teams to distinguish between normal application authentication and potential anomalies, which could indicate compromised credentials or malicious activities. If confirmed malicious, attackers could gain unauthorized access to resources, leading to data breaches or further exploitation within the environment.

## MITRE ATT&CK

- T1078.004

## Analytic Stories

- Azure Active Directory Account Takeover
- NOBELIUM Group

## Data Sources

- Azure Active Directory Sign-in activity

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.004/azure_ad_service_principal_authentication/azure_ad_service_principal_authentication.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_service_principal_authentication.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
