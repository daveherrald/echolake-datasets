# Linux Auditd Auditd Daemon Start

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the (re)initialization of the Linux audit daemon (auditd) by identifying log entries of type DAEMON_START. This event indicates that the audit subsystem has resumed logging after being stopped or has started during system boot. While DAEMON_START may be expected during reboots or legitimate configuration changes, it can also signal attempts to re-enable audit logging after evasion, or restarts with modified or reduced rule sets. Monitoring this event in correlation with DAEMON_END, DAEMON_ABORT, and auditctl activity provides visibility into the continuity and integrity of audit logs. Frequent or unexplained DAEMON_START events should be investigated, especially if they are not accompanied by valid administrative or system activity.

## MITRE ATT&CK

- T1562.012

## Analytic Stories

- Compromised Linux Host

## Data Sources

- Linux Auditd Daemon Start

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.012/auditd_daemon_type/linux_auditd_daemon.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_auditd_daemon_start.yml)*
