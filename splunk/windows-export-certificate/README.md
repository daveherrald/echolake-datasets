# Windows Export Certificate

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the export of a certificate from the Windows Certificate Store. It leverages the Certificates Lifecycle log channel, specifically event ID 1007, to identify this activity. Monitoring certificate exports is crucial as certificates can be used for authentication to VPNs or private resources. If malicious actors export certificates, they could potentially gain unauthorized access to sensitive systems or data, leading to significant security breaches.

## MITRE ATT&CK

- T1552.004
- T1649

## Analytic Stories

- Windows Certificate Services

## Data Sources

- Windows Event Log CertificateServicesClient 1007

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1649/atomic_red_team/certificateservices-lifecycle.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_export_certificate.yml)*
