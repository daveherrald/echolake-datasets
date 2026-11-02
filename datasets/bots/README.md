# Boss of the SOC (BOTS) Datasets

Security datasets from Splunk's Boss of the SOC competition series. Each version contains realistic attack scenarios with multi-source telemetry (Windows event logs, network traffic, IDS alerts, web server logs, and more).

## Datasets

| Directory | Description |
|-----------|-------------|
| botsv1 | 2016 — po1s0n1vy hacktivist attacks against Wayne Corp |
| botsv2 | 2017 — APT scenarios with broader data sources |
| botsv3 | 2018 — Advanced attack scenarios |
| botsv2-attack-only | Attack-only subset of BOTSv2 |
| botsv1-2026, botsv2-2026, etc. | Time-shifted copies with timestamps moved to 2026 (see below) |

## 2026 Time-Shifted Versions

The original BOTS datasets have timestamps from 2016–2018. Many security tools, SIEM correlation rules, and detection pipelines expect recent data — events from years ago may be ignored, filtered, or mishandled.

The `-2026` versions are identical to the originals except that all timestamps have been shifted forward to 2026, preserving the relative timing between events. This makes them usable in environments that expect current-year data without modifying your ingestion pipeline.

## Format

Gzip-compressed native logs in text, JSONL, and Windows Event Log XML formats. Each manifest records the format and sourcetype for every object.

## Integrity maintenance

Every remote object in the BOTS manifests has an immutable SHA-256 digest. A completed checkpoint is treated as final, so an ordinary rerun performs no S3 requests. To refresh the catalog after an intentional source change, build a separate checkpoint first:

```bash
python3 scripts/acquire_bots_checksums.py \
  --output scripts/data/bots_sha256.next.json \
  --head-only
```

The metadata-only pass exits nonzero when S3 does not return full-object SHA-256 values. Resume with the same output path to stream and hash those objects. Validate the completed checkpoint before replacing the committed catalog:

```bash
python3 scripts/acquire_bots_checksums.py \
  --output scripts/data/bots_sha256.next.json
python3 scripts/acquire_bots_checksums.py \
  --output scripts/data/bots_sha256.next.json \
  --validate-only
mv scripts/data/bots_sha256.next.json scripts/data/bots_sha256.json
python3 scripts/generate_splunk_metadata.py --write
python3 scripts/generate_splunk_metadata.py --check
```

The bucket uses requester-pays access. The acquisition script checkpoints each result in the selected output file, records S3 audit metadata, and never treats an ETag as a SHA-256 digest.

## License

The BOTS datasets are released under [CC0-1.0 (Creative Commons Zero)](https://creativecommons.org/publicdomain/zero/1.0/) by Splunk, Inc. This places them in the public domain.

- **Source:** [splunk/botsv1](https://github.com/splunk/botsv1), [splunk/botsv2](https://github.com/splunk/botsv2), [splunk/botsv3](https://github.com/splunk/botsv3)
- **SPDX identifier:** CC0-1.0
