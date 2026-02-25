# EchoLake Datasets

Curated security datasets for [EchoLake](https://github.com/daveherrald/echolake), the security data replay tool.

## Quick Start

```bash
pip install echolake

echolake echo \
  --output ./replayed-logs

echolake echo \
  --output ./replayed-logs
```

## Datasets

| Path | Count | Description |
|------|-------|-------------|

# Search by technique

# Replay a specific detection
echolake echo \
  --output ./replayed
```

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
```

### From a local clone

```bash
git clone https://github.com/daveherrald/echolake-datasets.git
```

## License

This repository is released under the [MIT License](LICENSE).

The datasets within this repository reference and include data from third-party sources under their own licenses:

