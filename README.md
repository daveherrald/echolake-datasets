# EchoLake Datasets

Curated security datasets for [EchoLake](https://github.com/daveherrald/echolake), the security data replay tool.

## Quick Start

```bash
pip install echolake

# Replay a Splunk detection dataset
echolake replay \
  --dataset github:daveherrald/echolake-datasets/datasets/splunk-detections/access-lsass-memory-for-dump-creation \
  --output ./replayed-logs

# Replay BOTSv1
echolake replay \
  --dataset github:daveherrald/echolake-datasets/datasets/botsv1 \
  --output ./replayed-logs
```

## Datasets

| Path | Count | Description |
|------|-------|-------------|
| [datasets/botsv1/](datasets/botsv1/) | 1 | Boss of the SOC v1 (22 sourcetypes, ~33M events) |
| [datasets/botsv2/](datasets/botsv2/) | 1 | Boss of the SOC v2 (93+ sourcetypes, ~24M events) |
| [datasets/botsv3/](datasets/botsv3/) | 1 | Boss of the SOC v3 (99+ sourcetypes, ~2M events) |
| [datasets/splunk-detections/](datasets/splunk-detections/) | 1,866 | Splunk Security Content detection datasets |

## Splunk Detections

1,866 datasets covering 327+ MITRE ATT&CK techniques across endpoint, cloud, network, and web detections. Each dataset references sample attack data from Splunk's attack_data repository.

```bash
# Search by technique
grep -r "T1003" datasets/splunk-detections/*/dataset.yaml

# Replay a specific detection
echolake replay \
  --dataset github:daveherrald/echolake-datasets/datasets/splunk-detections/windows-event-log-cleared \
  --output ./replayed
```

## Boss of the SOC (BOTS)

| Dataset | Compressed | Events | Sourcetypes |
|---------|-----------|--------|-------------|
| [botsv1](datasets/botsv1/) | ~1.8 GB | ~33M | 22 |
| [botsv2](datasets/botsv2/) | ~6 GB | ~24M | 93+ |
| [botsv3](datasets/botsv3/) | ~320 MB | ~2M | 99+ |

## Dataset Format

Each dataset directory contains a `dataset.yaml` manifest:

```yaml
metadata:
  name: "access-lsass-memory-for-dump-creation"
  version: "12.0.0"
  description: "..."
  tags: [ttp, credential-access]
  mitre_attack:
    techniques:
      - id: T1003.001
        name: LSASS Memory

files:
  references:
    - uri: https://media.githubusercontent.com/media/splunk/attack_data/...
      format: text
      schema: raw

defaults:
  replay:
    delta_factor: 1.0
    target_time: now-1h
```

## Usage with EchoLake

### From GitHub (recommended)

```bash
echolake replay --dataset github:daveherrald/echolake-datasets/datasets/splunk-detections/DATASET_NAME --output ./out
```

### From a local clone

```bash
git clone https://github.com/daveherrald/echolake-datasets.git
echolake replay --dataset local:./echolake-datasets/datasets/splunk-detections/DATASET_NAME --output ./out
```

## License

This repository is released under the [MIT License](LICENSE).

The datasets within this repository reference and include data from third-party sources under their own licenses:

- **BOTS datasets**: Released under [CC0-1.0 (Creative Commons Zero)](https://creativecommons.org/publicdomain/zero/1.0/) by Splunk, Inc. See [splunk/botsv1](https://github.com/splunk/botsv1), [splunk/botsv2](https://github.com/splunk/botsv2), [splunk/botsv3](https://github.com/splunk/botsv3).
- **Splunk detection datasets**: Detection logic from [splunk/security_content](https://github.com/splunk/security_content) and sample attack data from [splunk/attack_data](https://github.com/splunk/attack_data), both licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) by Splunk, Inc.
