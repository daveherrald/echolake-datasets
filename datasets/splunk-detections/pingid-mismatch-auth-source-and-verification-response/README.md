# PingID Mismatch Auth Source and Verification Response

**Type:** TTP

**Author:** Steven Dick

## Description

This dataset contains sample data for identifying discrepancies between the IP address of an authentication event and the IP address of the verification response event, focusing on differences in the originating countries. It leverages JSON logs from PingID, comparing the 'auth_Country' and 'verify_Country' fields. This activity is significant as it may indicate suspicious sign-in behavior, such as account compromise or unauthorized access attempts. If confirmed malicious, this could allow attackers to bypass authentication mechanisms, potentially leading to unauthorized access to sensitive systems and data.

## MITRE ATT&CK

- T1621
- T1556.006
- T1098.005

## Analytic Stories

- Compromised User Account

## Data Sources

- PingID

## Sample Data

- **Source:** PINGID
  **Sourcetype:** _json
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1621/pingid/pingid.log


---

*Source: [Splunk Security Content](detections/application/pingid_mismatch_auth_source_and_verification_response.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
