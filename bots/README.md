# Boss of the SOC (BOTS) Datasets

EchoLake dataset manifests for Splunk's [Boss of the SOC](https://github.com/splunk/securitydatasets) competition datasets.

## Available Datasets

| Dataset | Year | Size | Sourcetypes | Format |
|---------|------|------|-------------|--------|
| [botsv1](botsv1/) | 2016 | ~1.8 GB | 22 | CSV |
| [botsv1-small](botsv1-small/) | 2016 | ~530 MB | 3 | CSV |
| [botsv1-tiny](botsv1-tiny/) | 2016 | ~357 KB | 3 | CSV |
| [botsv2](botsv2/) | 2017 | 16.4 GB | 100+ | Splunk indexed |
| [botsv3](botsv3/) | 2019 | 320 MB | 100+ | Splunk indexed |

## Usage

```bash
# BOTSv1-tiny (bundled, no download needed)
echolake replay \
  --dataset github:daveherrald/echolake-datasets/bots/botsv1-tiny \
  --output ./replayed-bots

# BOTSv1 full (downloads ~1.8GB from GitHub Release)
echolake replay \
  --dataset github:daveherrald/echolake-datasets/bots/botsv1 \
  --output ./replayed-bots
```

## Data Files

**BOTSv1 and botsv1-small** data files are available as [GitHub Release assets](https://github.com/daveherrald/echolake-datasets/releases/tag/v1.0.0). EchoLake downloads them automatically when you use a `github:` dataset reference.

**BOTSv1-tiny** files are bundled directly in this repository (~357KB).

**BOTSv2 and BOTSv3** are manifest-only. The actual data requires Splunk to export. See the dataset.yaml files for download URLs.

## License

All BOTS datasets are released under CC0-1.0 (Public Domain) by Splunk.
