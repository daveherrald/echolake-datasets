# Windows SIP WinVerifyTrust Failed Trust Validation

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

The following analytic detects failed trust validation attempts using Windows Event Log - CAPI2 (CryptoAPI 2). It specifically triggers on EventID 81, which indicates that "The digital signature of the object did not verify." This detection leverages the CAPI2 Operational log to identify instances where digital signatures fail to validate. Monitoring this activity is crucial as it can indicate attempts to execute untrusted or potentially malicious binaries. If confirmed malicious, this activity could allow attackers to bypass security controls and execute unauthorized code, leading to potential system compromise.

## MITRE ATT&CK

- T1553.003

## Analytic Stories

- Subvert Trust Controls SIP and Trust Provider Hijacking

## Data Sources

- Windows Event Log CAPI2 81

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-CAPI2/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1553.003/sip/capi2-operational.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_sip_winverifytrust_failed_trust_validation.yml)*
