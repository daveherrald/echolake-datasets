# Cisco AI Defense Security Alerts by Application Name

**Type:** Anomaly

**Author:** Bhavin Patel, Splunk

## Description

The search surfaces alerts from the Cisco AI Defense product for potential attacks against the AI models running in your environment. This analytic identifies security events within Cisco AI Defense by examining event messages, actions, and policy names. It focuses on connections and applications associated with specific guardrail entities and ruleset types. By aggregating and analyzing these elements, the search helps detect potential policy violations and security threats, enabling proactive defense measures and ensuring network integrity.

## Analytic Stories

- Critical Alerts

## Data Sources

- Cisco AI Defense Alerts

## Sample Data

- **Source:** cisco_ai_defense
  **Sourcetype:** cisco:ai:defense
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/cisco_ai_defense_alerts/cisco_ai_defense_alerts.json


---

*Source: [Splunk Security Content](detections/application/cisco_ai_defense_security_alerts_by_application_name.yml)*
