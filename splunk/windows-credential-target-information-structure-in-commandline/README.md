# Windows Credential Target Information Structure in Commandline

**Type:** TTP

**Author:** Raven Tait, Splunk

## Description

Detects DNS-based Kerberos coercion attacks where adversaries inject marshaled credential structures into DNS records to spoof SPNs and redirect authentication such as in CVE-2025-33073. This detection leverages process creation events looking for specific CREDENTIAL_TARGET_INFORMATION structures.

## MITRE ATT&CK

- T1557.001
- T1187
- T1071.004

## Analytic Stories

- Compromised Windows Host
- Suspicious DNS Traffic
- Local Privilege Escalation With KrbRelayUp
- Kerberos Coercion with DNS

## Data Sources

- Sysmon EventID 1

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1071.004/kerberos_coercion/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_credential_target_information_structure_in_commandline.yml)*
