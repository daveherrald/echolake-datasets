# Boss of the SOC (BOTS) Datasets

EchoLake dataset manifests for Splunk's [Boss of the SOC](https://github.com/splunk/securitydatasets) competition datasets.

## Available Datasets

| Dataset | Year | Size | Sourcetypes | Format |
|---------|------|------|-------------|--------|
| [botsv1](botsv1/) | 2016 | ~1.8 GB | 22 | CSV |
| [botsv2](botsv2/) | 2017 | 16.4 GB | 100+ | Splunk indexed |
| [botsv3](botsv3/) | 2019 | 320 MB | 100+ | Splunk indexed |

## Usage

```bash
# BOTSv1 (downloads ~1.8GB from S3)
echolake replay \
  --dataset local:bots/botsv1 \
  --output ./replayed-bots \
  --path-template "{sourcetype}/{filename}"
```

## Data Source

BOTSv1 CSV-by-sourcetype files are published at `s3.amazonaws.com/botsdataset/botsv1/csv-by-sourcetype/`.

BOTSv2 and BOTSv3 are manifest-only. The actual data requires Splunk to export.

## License

All BOTS datasets are released under CC0-1.0 (Public Domain) by Splunk.
