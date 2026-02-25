# Cisco Secure Firewall - Oracle E-Business Suite Correlation

**Type:** TTP

**Author:** Nasreddine Bencherchali, Splunk, Talos NTDR

## Description

This correlation rule identifies potential exploitation attempts of Oracle E-Business Suite vulnerabilities (CVE-2025-61882 and CVE-2025-61884) by correlating multiple intrusion signatures from Cisco Secure Firewall Threat Defense logs.
The detection looks for specific signatures that indicate attempts to exploit the TemplatePreview functionality and vulnerable SyncServlet endpoints as well as post compromise activity involving Cl0p.
By correlating these signatures, the analytic aims to identify coordinated exploitation attempts that may indicate an attacker is targeting Oracle E-Business Suite installations.
Security teams should investigate any instances of these correlated signatures, especially if they are found in conjunction with other suspicious network activity or on systems that should not be exposed to such threats.


## MITRE ATT&CK

- T1190

## Analytic Stories

- Cisco Secure Firewall Threat Defense Analytics
- Oracle E-Business Suite Exploitation

## Data Sources

- Cisco Secure Firewall Threat Defense Intrusion Event

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:sfw:estreamer
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_secure_firewall_threat_defense/oracle_e_business_suite/oracle_e_business_suite.log


---

*Source: [Splunk Security Content](detections/network/cisco_secure_firewall___oracle_e_business_suite_correlation.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
