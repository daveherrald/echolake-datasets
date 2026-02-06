# Cisco Privileged Account Creation with Suspicious SSH Activity

**Type:** Correlation

**Author:** Nasreddine Bencherchali, Splunk

## Description

This analytic detects a correlation between privileged account creation on Cisco IOS devices and subsequent inbound SSH connections to non-standard ports or sshd_operns by correlating risk events
This correlation identifies when both "Cisco IOS Suspicious Privileged Account Creation" and SSH-related Snort detections ("SSH Connection to sshd_operns" or "SSH Connection to Non-Standard Port") fire for the same network device.
This behavior is highly indicative of persistence establishment following initial compromise.


## MITRE ATT&CK

- T1021.004
- T1136
- T1078

## Analytic Stories

- Cisco Secure Firewall Threat Defense Analytics
- Salt Typhoon

## Data Sources


## Sample Data

- **Source:** not_applicable
  **Sourcetype:** stash
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/emerging_threats/SaltTyphoon/salttyphoon_correlation.log


---

*Source: [Splunk Security Content](detections/network/cisco_privileged_account_creation_with_suspicious_ssh_activity.yml)*
