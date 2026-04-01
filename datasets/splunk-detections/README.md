# Splunk Detection Datasets

1,867 datasets of sample attack data paired with detection logic from Splunk's [Security Content](https://github.com/splunk/security_content) project. Each dataset provides the telemetry needed to validate a specific detection rule.

## Structure

```
abnormally-high-number-of-cloud-infrastructure-api-calls/
  dataset.yaml    # Metadata, description, MITRE mapping, data source references
  README.md       # Quick summary and usage
```

## Data Sources

Each dataset references sample attack data hosted in Splunk's [attack_data](https://github.com/splunk/attack_data) repository. The `dataset.yaml` file contains URIs pointing to the original source files.

## License

Both the detection logic and sample attack data are released under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) by Splunk, Inc.

- **Detection logic:** [splunk/security_content](https://github.com/splunk/security_content) (Apache 2.0)
- **Sample attack data:** [splunk/attack_data](https://github.com/splunk/attack_data) (Apache 2.0)
