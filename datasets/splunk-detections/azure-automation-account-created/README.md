# Azure Automation Account Created

**Type:** TTP

**Author:** Mauricio Velazco, Brian Serocki, Splunk

## Description

This dataset contains sample data for detecting the creation of a new Azure Automation account within an Azure tenant. It leverages Azure Audit events, specifically the Azure Activity log category, to identify when an account is created or updated. This activity is significant because Azure Automation accounts can be used to automate tasks and orchestrate actions across Azure and on-premise environments. If an attacker creates an Automation account with elevated privileges, they could maintain persistence, execute malicious runbooks, and potentially escalate privileges or execute code on virtual machines, posing a significant security risk.

## MITRE ATT&CK

- T1136.003

## Analytic Stories

- Azure Active Directory Persistence

## Data Sources

- Azure Audit Create or Update an Azure Automation account

## Sample Data

- **Source:** mscs:azure:audit
  **Sourcetype:** mscs:azure:audit
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.003/azure_automation_account/azure-activity.log


---

*Source: [Splunk Security Content](detections/cloud/azure_automation_account_created.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
