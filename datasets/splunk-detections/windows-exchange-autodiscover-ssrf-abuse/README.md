# Windows Exchange Autodiscover SSRF Abuse

**Type:** TTP

**Author:** Michael Haag, Nathaniel Stearns, Splunk

## Description

This analytic identifies potential exploitation attempts of ProxyShell (CVE-2021-34473, CVE-2021-34523, CVE-2021-31207) and ProxyNotShell (CVE-2022-41040, CVE-2022-41082) vulnerabilities in Microsoft Exchange Server. The detection focuses on identifying the SSRF attack patterns used in these exploit chains. The analytic monitors for suspicious POST requests to /autodiscover/autodiscover.json endpoints that may indicate attempts to enumerate LegacyDN attributes as part of initial reconnaissance. It also detects requests containing X-Rps-CAT parameters that could indicate attempts to impersonate Exchange users and access the PowerShell backend. Additionally, it looks for MAPI requests that may be used to obtain user SIDs, along with suspicious user agents (particularly Python-based) commonly used in automated exploit attempts. If successful, these attacks can lead to remote code execution as SYSTEM, allowing attackers to deploy webshells, access mailboxes, or gain persistent access to the Exchange server and potentially the broader network environment.

## MITRE ATT&CK

- T1190
- T1133

## Analytic Stories

- ProxyShell
- BlackByte Ransomware
- ProxyNotShell
- Seashell Blizzard

## Data Sources

- Windows IIS

## Sample Data

- **Source:** ms:iis:splunk
  **Sourcetype:** ms:iis:splunk
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/proxyshell/proxyshell.log


---

*Source: [Splunk Security Content](detections/web/windows_exchange_autodiscover_ssrf_abuse.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
