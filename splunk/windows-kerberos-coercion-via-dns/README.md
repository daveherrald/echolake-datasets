# Windows Kerberos Coercion via DNS

**Type:** TTP

**Author:** Raven Tait, Splunk

## Description

Detects DNS-based Kerberos coercion attacks where adversaries inject marshaled credential structures into DNS records to spoof SPNs and redirect authentication such as in CVE-2025-33073. This detection leverages Windows Security Event Codes 5136, 5137, 4662, looking for DNS events with specific CREDENTIAL_TARGET_INFORMATION entries.

## MITRE ATT&CK

- T1071.004
- T1557.001
- T1187

## Analytic Stories

- Compromised Windows Host
- Suspicious DNS Traffic
- Local Privilege Escalation With KrbRelayUp
- Kerberos Coercion with DNS

## Data Sources

- Windows Event Log Security 4662
- Windows Event Log Security 5136
- Windows Event Log Security 5137

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1071.004/kerberos_coercion/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_kerberos_coercion_via_dns.yml)*
