# Azure Automation Runbook Created

**Type:** TTP

**Author:** Mauricio Velazco, Brian Serocki, Splunk

## Description

The following analytic detects the creation of a new Azure Automation Runbook within an Azure tenant. It leverages Azure Audit events, specifically the Azure Activity log category, to identify when a new Runbook is created or updated. This activity is significant because adversaries with privileged access can use Runbooks to maintain persistence, escalate privileges, or execute malicious code. If confirmed malicious, this could lead to unauthorized actions such as creating Global Administrators, executing code on VMs, and compromising the entire Azure environment.

## MITRE ATT&CK

- T1136.003

## Analytic Stories

- Azure Active Directory Persistence

## Data Sources

- Azure Audit Create or Update an Azure Automation Runbook

## Sample Data

- **Source:** mscs:azure:audit
  **Sourcetype:** mscs:azure:audit
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.004/azure_automation_runbook/azure-activity.log


---

*Source: [Splunk Security Content](detections/cloud/azure_automation_runbook_created.yml)*
