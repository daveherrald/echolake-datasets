# Splunk Security Content Datasets

1,866 EchoLake datasets generated from [Splunk Security Content](https://github.com/splunk/security_content) detections.

## Usage

```bash
echolake replay \
  --dataset github:daveherrald/echolake-datasets/splunk/access-lsass-memory-for-dump-creation \
  --output ./replayed-logs \
  --target-time now-1h
```

## Coverage

- **Total Datasets:** 1,866
- **MITRE ATT&CK Techniques:** 327+
- **Detection Types:** TTP, Hunting, Anomaly
- **Data Sources:** Windows, Linux, Cloud (AWS/Azure/GCP), Network, Web

## Search by MITRE ATT&CK Technique

```bash
grep -r "T1003" splunk/*/dataset.yaml      # Credential Dumping
grep -r "T1059" splunk/*/dataset.yaml      # Command and Scripting
grep -r "T1190" splunk/*/dataset.yaml      # Exploit Public-Facing App
```

## Dataset Structure

Each dataset directory contains:
- `dataset.yaml` - EchoLake manifest with metadata, MITRE mappings, and data references
- `README.md` - Detection description, data sources, and analytic stories

## Data Sources

Datasets reference sample attack data from Splunk's attack_data repository at
`https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/`.

Data is downloaded on-demand during replay operations.

## Statistics

See [STATISTICS.md](STATISTICS.md) for detailed breakdowns.

## License

The detection logic in these datasets is derived from [Splunk Security Content](https://github.com/splunk/security_content), licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) by Splunk, Inc.

The sample attack data referenced by these datasets is from [splunk/attack_data](https://github.com/splunk/attack_data), also licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) by Splunk, Inc.

- **SPDX identifier:** Apache-2.0

## Source

Generated from [Splunk Security Content](https://github.com/splunk/security_content) detections.
