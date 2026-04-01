# Windows Certutil Root Certificate Addition

**Type:** TTP

**Author:** Teoderick Contreras, Nasreddine Bencherchali, Splunk

## Description

This dataset contains sample data for detecting the use of certutil.exe to add a certificate to the Root certificate store using the "-addstore" flag.
In this case, the certificate is loaded from a temporary file path (e.g., %TEMP%) or other uncommon locations (e.g. C:\\Users\\Public\\), which is highly suspicious and uncommon in legitimate administrative activity.
This behavior may indicate an adversary is installing a malicious root certificate to intercept HTTPS traffic, impersonate trusted entities, or bypass security controls. 
The use of flags such as -f (force) and -Enterprise, combined with loading .tmp files from user-writable locations, is consistent with post-exploitation activity seen in credential theft and adversary-in-the-middle (AiTM) attacks. 
This should be investigated immediately, especially if correlated with unauthorized privilege use or prior certificate modifications.
You should monitor when new certificates are added to the root store because this store is what your system uses to decide which websites, apps, and software can be trusted. 
If an attacker manages to add their own certificate there, they can silently intercept encrypted traffic, impersonate trusted websites, or make malicious programs look safe. 
This means they could steal sensitive data, bypass security tools, and keep access to your system even after other malware is removed.


## MITRE ATT&CK

- T1587.003

## Analytic Stories

- Secret Blizzard

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1587.003/add_store_cert/addstore_cert.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_certutil_root_certificate_addition.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
