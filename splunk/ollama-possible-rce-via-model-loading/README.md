# Ollama Possible RCE via Model Loading

**Type:** Anomaly

**Author:** Rod Soto

## Description

Detects Ollama server errors and failures during model loading operations that may indicate malicious model injection, path traversal attempts, or exploitation of model loading mechanisms to achieve remote code execution. Adversaries may attempt to load specially crafted malicious models or exploit vulnerabilities in the model loading process to execute arbitrary code on the server. This detection monitors error messages and failure patterns that could signal attempts to abuse model loading functionality for malicious purposes.

## MITRE ATT&CK

- T1190

## Analytic Stories

- Suspicious Ollama Activities

## Data Sources

- Ollama Server

## Sample Data

- **Source:** app.log
  **Sourcetype:** ollama:server
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/ollama/app.log


---

*Source: [Splunk Security Content](detections/application/ollama_possible_rce_via_model_loading.yml)*
