# Splunk AppDynamics Secure Application Alerts

**Type:** Anomaly

**Author:** Ryan Long, Bhavin Patel, Splunk

## Description

This dataset contains sample data for leveraging alerts from Splunk AppDynamics SecureApp, which identifies and monitors exploit attempts targeting business applications. The primary attack observed involves exploiting vulnerabilities in web applications, including injection attacks (SQL, API abuse), deserialization vulnerabilities, remote code execution attempts, LOG4J and zero day attacks. These attacks are typically aimed at gaining unauthorized access, exfiltrating sensitive data, or disrupting application functionality.

Splunk AppDynamics SecureApp provides real-time detection of these threats by analyzing application-layer events and correlating attack behavior with known vulnerability signatures. This detection methodology helps the Security Operations Center (SOC) by:

* Identifying active exploitation attempts in real-time, allowing for quicker incident response.
* Categorizing attack severity to prioritize remediation efforts based on risk level.
* Providing visibility into attacker tactics, including source IP, attack techniques, and affected applications.
* Generating risk-based scoring and contextual alerts to enhance decision-making within SOC workflows.
* Helping analysts determine whether an attack was merely an attempt or if it successfully exploited a vulnerability.

By leveraging this information, SOC teams can proactively mitigate security threats, patch vulnerable applications, and enforce security controls to prevent further exploitation.


## Analytic Stories

- Critical Alerts

## Data Sources

- Splunk AppDynamics Secure Application Alert

## Sample Data

- **Source:** AppDynamics Security
  **Sourcetype:** appdynamics_security
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/alerts/cisco_secure_app_alerts.log


---

*Source: [Splunk Security Content](detections/application/splunk_appdynamics_secure_application_alerts.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
