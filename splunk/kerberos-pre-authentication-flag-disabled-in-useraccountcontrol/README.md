# Kerberos Pre-Authentication Flag Disabled in UserAccountControl

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects when the Kerberos Pre-Authentication flag is disabled in a user account, using Windows Security Event 4738. This event indicates a change in the UserAccountControl property of a domain user object. Disabling this flag allows adversaries to perform offline brute force attacks on the user's password using the AS-REP Roasting technique. This activity is significant as it can be used by attackers with existing privileges to escalate their access or maintain persistence. If confirmed malicious, this could lead to unauthorized access and potential compromise of sensitive information.

## MITRE ATT&CK

- T1558.004

## Analytic Stories

- Active Directory Kerberos Attacks
- BlackSuit Ransomware

## Data Sources

- Windows Event Log Security 4738

## Sample Data

- **Source:** WinEventLog:Security
  **Sourcetype:** WinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558.004/powershell/windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/kerberos_pre_authentication_flag_disabled_in_useraccountcontrol.yml)*
