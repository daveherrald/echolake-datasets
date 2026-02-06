# Ollama Excessive API Requests

**Type:** Anomaly

**Author:** Rod Soto

## Description

Detects potential Distributed Denial of Service (DDoS) attacks or rate limit abuse against Ollama API endpoints by identifying excessive request volumes from individual client IP addresses. This detection monitors GIN-formatted Ollama server logs to identify clients generating abnormally high request rates within short time windows, which may indicate automated attacks, botnet activity, or resource exhaustion attempts targeting local AI model infrastructure.

## MITRE ATT&CK

- T1498

## Analytic Stories

- Suspicious Ollama Activities

## Data Sources

- Ollama Server

## Sample Data

- **Source:** server.log
  **Sourcetype:** ollama:server
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/ollama/server.log


---

*Source: [Splunk Security Content](detections/application/ollama_excessive_api_requests.yml)*
