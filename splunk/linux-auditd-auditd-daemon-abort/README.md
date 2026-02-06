# Linux Auditd Auditd Daemon Abort

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the abnormal termination of the Linux audit daemon (auditd) by identifying DAEMON_ABORT events in audit logs. These terminations suggest a serious failure of the auditing subsystem, potentially due to resource exhaustion, corruption, or malicious interference. Unlike a clean shutdown, DAEMON_ABORT implies that audit logging may have been disabled without system administrator intent. Alerts should be generated on detection and correlated with DAEMON_START, DAEMON_END, and system logs to determine root cause. If no DAEMON_START follows soon after, or this pattern repeats, it indicates a high-severity issue that impacts log integrity and should be immediately investigated.

## MITRE ATT&CK

- T1562.012

## Analytic Stories

- Compromised Linux Host

## Data Sources

- Linux Auditd Daemon Abort

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.012/auditd_daemon_type/linux_auditd_daemon.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_auditd_daemon_abort.yml)*
