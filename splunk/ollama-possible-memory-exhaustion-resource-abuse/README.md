# Ollama Possible Memory Exhaustion Resource Abuse

**Type:** Anomaly

**Author:** Rod Soto

## Description

Detects abnormal memory allocation patterns and excessive runner operations in Ollama that may indicate resource exhaustion attacks, memory abuse through malicious model loading, or attempts to degrade system performance by overwhelming GPU/CPU resources. Adversaries may deliberately load multiple large models, trigger repeated model initialization cycles, or exploit memory allocation mechanisms to exhaust available system resources, causing denial of service conditions or degrading performance for legitimate users.

## MITRE ATT&CK

- T1499

## Analytic Stories

- Suspicious Ollama Activities

## Data Sources

- Ollama Server

## Sample Data

- **Source:** server.log
  **Sourcetype:** ollama:server
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/ollama/server.log


---

*Source: [Splunk Security Content](detections/application/ollama_possible_memory_exhaustion_resource_abuse.yml)*
