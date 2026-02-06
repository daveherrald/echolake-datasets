# Windows Admon Default Group Policy Object Modified

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects modifications to the default Group Policy Objects (GPOs) in an Active Directory environment. It leverages Splunk's Admon to monitor updates to the "Default Domain Policy" and "Default Domain Controllers Policy." This activity is significant because changes to these default GPOs can indicate an adversary with privileged access attempting to gain further control, establish persistence, or deploy malware across multiple hosts. If confirmed malicious, such modifications could lead to widespread policy enforcement changes, unauthorized access, and potential compromise of the entire domain environment.

## MITRE ATT&CK

- T1484.001

## Analytic Stories

- Active Directory Privilege Escalation
- Sneaky Active Directory Persistence Tricks

## Data Sources

- Windows Active Directory Admon

## Sample Data

- **Source:** ActiveDirectory
  **Sourcetype:** ActiveDirectory
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1484.001/default_domain_policy_modified/windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_admon_default_group_policy_object_modified.yml)*
