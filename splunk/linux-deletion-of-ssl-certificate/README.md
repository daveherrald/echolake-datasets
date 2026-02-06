# Linux Deletion of SSL Certificate

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the deletion of SSL certificates on a Linux machine. It leverages filesystem event logs to identify when files with extensions .pem or .crt are deleted from the /etc/ssl/certs/ directory. This activity is significant because attackers may delete or modify SSL certificates to disable security features or evade defenses on a compromised system. If confirmed malicious, this behavior could indicate an attempt to disrupt secure communications, evade detection, or execute a destructive payload, potentially leading to significant security breaches and data loss.

## MITRE ATT&CK

- T1070.004
- T1485

## Analytic Stories

- AcidRain
- AcidPour

## Data Sources

- Sysmon for Linux EventID 11

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/acidrain/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_deletion_of_ssl_certificate.yml)*
