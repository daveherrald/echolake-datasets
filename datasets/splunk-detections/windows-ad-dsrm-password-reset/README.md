# Windows AD DSRM Password Reset

**Type:** TTP

**Author:** Dean Luxton

## Description

This dataset contains sample data for detecting attempts to reset the Directory Services Restore Mode (DSRM) administrator password on a Domain Controller. It leverages event code 4794 from the Windows Security Event Log, specifically looking for events where the DSRM password reset is attempted. This activity is significant because the DSRM account can be used similarly to a local administrator account, providing potential persistence for an attacker. If confirmed malicious, this could allow an attacker to maintain administrative access to the Domain Controller, posing a severe risk to the domain's security.

## MITRE ATT&CK

- T1098

## Analytic Stories

- Sneaky Active Directory Persistence Tricks
- Scattered Lapsus$ Hunters

## Data Sources

- Windows Event Log Security 4794

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/dsrm_account/windows-security-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_ad_dsrm_password_reset.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
