# Kerberos TGT Request Using RC4 Encryption

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects a Kerberos Ticket Granting Ticket (TGT) request using RC4-HMAC encryption (type 0x17) by leveraging Event 4768. This encryption type is outdated and its presence may indicate an OverPass The Hash attack. Monitoring this activity is crucial as it can signify credential theft, allowing adversaries to authenticate to the Kerberos Distribution Center (KDC) using a stolen NTLM hash. If confirmed malicious, this could enable unauthorized access to systems and resources, potentially leading to lateral movement and further compromise within the network.

## MITRE ATT&CK

- T1550

## Analytic Stories

- Active Directory Kerberos Attacks
- Scattered Lapsus$ Hunters

## Data Sources

- Windows Event Log Security 4768

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1550/kerberos_tgt_request_using_rc4_encryption/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/kerberos_tgt_request_using_rc4_encryption.yml)*
