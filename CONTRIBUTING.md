# Contributing to EchoLake Datasets

Contributions are welcome! Here's how to add datasets to this repository.

## Adding a Dataset

### 1. Create a directory

```
<collection>/<dataset-name>/
  dataset.yaml
  README.md          # optional
  data/              # optional, for bundled files
```

### 2. Write the manifest

Every dataset needs a `dataset.yaml`:

```yaml
metadata:
  name: "my-dataset"
  version: "1.0.0"
  description: "Brief description of the dataset"
  author: "Your Name"
  tags:
    - category
    - relevant-tag

files:
  bundled: []        # Small files stored in the repo
  references:        # Large files stored externally
    - uri: https://example.com/data.csv.gz
      description: "Data file"
      format: csv

defaults:
  replay:
    delta_factor: 1.0
    base_time: earliest
    target_time: now-1h
```

### 3. Validate

```bash
python scripts/validate_manifests.py
```

### 4. Submit a PR

Open a pull request with your changes. The CI workflow will validate all manifests automatically.

## Guidelines

- **Bundled files** should be small (< 1 MB). Use `files.references` for larger data.
- **Filenames** must not contain colons (`:`). Use hyphens instead.
- **Dependencies** must use `github:` references, not `local:` paths.
- Each dataset must have a `metadata.name` field.
- Include MITRE ATT&CK technique IDs where applicable.

## Meta-Datasets

Meta-datasets are curated collections that reference other datasets via `dependencies`:

```yaml
dependencies:
  - dataset: "github:daveherrald/echolake-datasets/splunk/some-detection"
    version: "*"
    description: "Why this is included"
```

## Questions?

Open an issue on this repository or on the [EchoLake](https://github.com/daveherrald/echolake) project.
