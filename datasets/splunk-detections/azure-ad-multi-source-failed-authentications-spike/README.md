# Azure AD Multi-Source Failed Authentications Spike

**Type:** Hunting

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting potential distributed password spraying attacks in an Azure AD environment. It identifies a spike in failed authentication attempts across various user-and-IP combinations from multiple source IPs and countries, using different user agents. This detection leverages Azure AD SignInLogs, focusing on error code 50126 for failed authentications. This activity is significant as it indicates an adversary's attempt to bypass security controls by distributing login attempts. If confirmed malicious, this could lead to unauthorized access, data breaches, privilege escalation, and lateral movement within the organization's infrastructure.

## MITRE ATT&CK

- T1110.003
- T1110.004
- T1586.003

## Analytic Stories

- Azure Active Directory Account Takeover
- NOBELIUM Group

## Data Sources

- Azure Active Directory

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/azure_ad_distributed_spray/azure_ad_distributed_spray.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_multi_source_failed_authentications_spike.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
