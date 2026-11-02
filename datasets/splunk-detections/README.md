# Splunk Detection Datasets

1,866 datasets of sample attack data paired with detection logic from Splunk Security Content. Each manifest is generated from a pinned upstream rule and contains integrity-checked sample references.

## Current package facts

- Datasets: 1,866
- Sample references: 1,934
- Unique attack-data objects: 1,267
- Datasets with ATT&CK mappings: 1,853
- Reviewed upstream-unmapped datasets: 13

## Source lock

- `splunk/security_content`: `29ece397e8ab7f95fd9055e586dd541859075a9f`
- `splunk/attack_data`: `f5cea3c0980ca3f3c4c5dafc72330278b35ddbd3`
- MITRE ATT&CK Enterprise: v18.1 at `7ad8a86f41edc91dd37de0487b0c2f44ae3a3af7`

The immutable source definitions are recorded in [upstream.lock.yaml](upstream.lock.yaml). Each dataset README links to its pinned rule and sample objects.

## Metadata maintenance

Check generated manifests and documentation:

```bash
python3 scripts/generate_splunk_metadata.py --check
```

Regenerate after changing the committed source catalogs:

```bash
python3 scripts/generate_splunk_metadata.py --write
```

Refresh the source catalogs from local checkouts at the revisions in `upstream.lock.yaml`:

```bash
python3 scripts/generate_splunk_metadata.py --refresh-catalog \
  --security-content /path/to/security_content \
  --attack-data /path/to/attack_data \
  --attack-stix /path/to/enterprise-attack-18.1.json
```

## License and attribution

Splunk Security Content and attack data are provided under [Apache License 2.0](LICENSE). See [ATTRIBUTION.md](ATTRIBUTION.md) for copyright, source revisions, and EchoLake modifications.

MITRE ATT&CK names and tactics are provided under the [MITRE ATT&CK license](MITRE-ATTACK-LICENSE.txt).
