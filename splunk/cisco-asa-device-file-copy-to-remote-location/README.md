# Cisco ASA - Device File Copy to Remote Location

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This analytic detects file copy operations to remote locations on Cisco ASA devices via CLI or ASDM.
Adversaries may exfiltrate device files including configurations, logs, packet captures, or system data to remote servers using protocols like TFTP, FTP, HTTP, HTTPS, SMB, or SCP. While legitimate backups to centralized servers are common, copies to unexpected destinations may indicate data exfiltration to attacker-controlled infrastructure.
The detection monitors for command execution events (message ID 111008 or 111010) containing copy commands with remote protocol indicators (tftp:, ftp:, http:, https:, smb:, scp:).
Investigate copies to unexpected destinations, from non-administrative accounts, or outside approved maintenance windows.
We recommend adapting the detection filters to exclude known legitimate backup activities.


## MITRE ATT&CK

- T1005
- T1041
- T1048.003

## Analytic Stories

- Suspicious Cisco Adaptive Security Appliance Activity
- ArcaneDoor

## Data Sources

- Cisco ASA Logs

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:asa
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_asa/generic/cisco_asa_generic_logs.log


---

*Source: [Splunk Security Content](detections/application/cisco_asa___device_file_copy_to_remote_location.yml)*
