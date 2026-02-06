# EchoLake Datasets

Curated security datasets for [EchoLake](https://github.com/daveherrald/echolake), the security data replay tool.

## Quick Start

```bash
pip install echolake

# Replay a Splunk detection dataset
echolake replay \
  --dataset github:daveherrald/echolake-datasets/splunk/access-lsass-memory-for-dump-creation \
  --output ./replayed-logs

# Replay a curated attack collection
echolake replay \
  --dataset github:daveherrald/echolake-datasets/meta/ransomware-suite \
  --output ./replayed-logs

# Replay BOTSv1 (tiny subset, ~357KB)
echolake replay \
  --dataset github:daveherrald/echolake-datasets/bots/botsv1-tiny \
  --output ./replayed-logs
```

## Collections

| Collection | Datasets | Description |
|-----------|----------|-------------|
| [splunk/](splunk/) | 1,866 | Datasets from [Splunk Security Content](https://github.com/splunk/security_content) detections |
| [bots/](bots/) | 5 | [Boss of the SOC](https://github.com/splunk/securitydatasets) competition datasets |
| [meta/](meta/) | 7 | Curated collections of related datasets |

**Total: 1,878 datasets**

## Splunk Security Content

1,866 datasets covering 327+ MITRE ATT&CK techniques across endpoint, cloud, network, and web detections. Each dataset references sample attack data from Splunk's attack_data repository.

```bash
# Search by technique
grep -r "T1003" splunk/*/dataset.yaml

# Replay a specific detection
echolake replay \
  --dataset github:daveherrald/echolake-datasets/splunk/windows-event-log-cleared \
  --output ./replayed
```

## Boss of the SOC (BOTS)

| Dataset | Size | Events | Format |
|---------|------|--------|--------|
| [botsv1](bots/botsv1/) | ~1.8 GB | ~33M | CSV (22 sourcetypes) |
| [botsv1-small](bots/botsv1-small/) | ~530 MB | ~8M | CSV (3 sourcetypes) |
| [botsv1-tiny](bots/botsv1-tiny/) | ~357 KB | ~1K | CSV (3 sourcetypes) |
| [botsv2](bots/botsv2/) | 16.4 GB | - | Splunk indexed (manifest only) |
| [botsv3](bots/botsv3/) | 320 MB | - | Splunk indexed (manifest only) |

BOTSv1 data files are available as [GitHub Release assets](https://github.com/daveherrald/echolake-datasets/releases/tag/v1.0.0).

## Meta-Datasets

Curated attack scenario collections that bundle related detections:

| Meta-Dataset | Datasets | MITRE Techniques |
|-------------|----------|------------------|
| [ransomware-suite](meta/ransomware-suite/) | 7 | T1486, T1490, T1489 |
| [credential-dumping-t1003](meta/credential-dumping-t1003/) | 7 | T1003.001-.003 |
| [aws-cloud-attacks](meta/aws-cloud-attacks/) | 8 | T1078.004, T1098, T1485 |
| [lateral-movement-suite](meta/lateral-movement-suite/) | 7 | T1021, T1047 |
| [web-exploitation-cves](meta/web-exploitation-cves/) | 8 | T1190, T1210 |
| [top-10-mitre-attacks](meta/top-10-mitre-attacks/) | 10 | Top 10 techniques |
| [sample-logs](meta/sample-logs/) | - | Sample data for testing |

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
echolake replay --dataset github:daveherrald/echolake-datasets/splunk/DATASET_NAME --output ./out
```

### From a local clone

```bash
git clone https://github.com/daveherrald/echolake-datasets.git
echolake replay --dataset local:./echolake-datasets/splunk/DATASET_NAME --output ./out
```

## License

MIT License. See [LICENSE](LICENSE).

BOTS datasets are released under CC0-1.0 by Splunk. Splunk Security Content detections are licensed under the Splunk Security Content License.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on adding datasets.
