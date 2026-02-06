# Okta New API Token Created

**Type:** TTP

**Author:** Michael Haag, Mauricio Velazco, Splunk

## Description

The following analytic detects the creation of a new API token within an Okta tenant. It uses OktaIm2 logs ingested via the Splunk Add-on for Okta Identity Cloud to identify events where the `system.api_token.create` command is executed. This activity is significant because creating a new API token can indicate potential account takeover attempts or unauthorized access, allowing an adversary to maintain persistence. If confirmed malicious, this could enable attackers to execute API calls, access sensitive data, and perform administrative actions within the Okta environment.

## MITRE ATT&CK

- T1078.001

## Analytic Stories

- Okta Account Takeover
- Scattered Lapsus$ Hunters

## Data Sources

- Okta

## Sample Data

- **Source:** Okta
  **Sourcetype:** OktaIM2:log
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.001/okta_new_api_token_created/okta_new_api_token_created.log


---

*Source: [Splunk Security Content](detections/application/okta_new_api_token_created.yml)*
