# Azure Runbook Webhook Created

**Type:** TTP

**Author:** Mauricio Velazco, Brian Serocki, Splunk

## Description

The following analytic detects the creation of a new Automation Runbook Webhook within an Azure tenant. It leverages Azure Audit events, specifically the "Create or Update an Azure Automation webhook" operation, to identify this activity. This behavior is significant because Webhooks can trigger Automation Runbooks via unauthenticated URLs exposed to the Internet, posing a security risk. If confirmed malicious, an attacker could use this to execute code, create users, or maintain persistence within the environment, potentially leading to unauthorized access and control over Azure resources.

## MITRE ATT&CK

- T1078.004

## Analytic Stories

- Azure Active Directory Persistence

## Data Sources

- Azure Audit Create or Update an Azure Automation webhook

## Sample Data

- **Source:** mscs:azure:audit
  **Sourcetype:** mscs:azure:audit
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.004/azure_runbook_webhook/azure-activity.log


---

*Source: [Splunk Security Content](detections/cloud/azure_runbook_webhook_created.yml)*
