# Azure AD AzureHound UserAgent Detected

**Type:** TTP

**Author:** Dean Luxton

## Description

This detection identifies the presence of the default AzureHound user-agent string within Microsoft Graph Activity logs and NonInteractive SignIn Logs. AzureHound is a tool used for gathering information about Azure Active Directory environments, often employed by security professionals for legitimate auditing purposes. However, it can also be leveraged by malicious actors to perform reconnaissance activities, mapping out the Azure AD infrastructure to identify potential vulnerabilities and targets for further exploitation. Detecting its usage can help in identifying unauthorized access attempts and preemptively mitigating potential security threats to your Azure environment.

## MITRE ATT&CK

- T1087.004
- T1526

## Analytic Stories

- Azure Active Directory Privilege Escalation
- Compromised User Account

## Data Sources

- Azure Active Directory NonInteractiveUserSignInLogs
- Azure Active Directory MicrosoftGraphActivityLogs

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.004/azurehound/azurehound.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_azurehound_useragent_detected.yml)*
