# Meta-Datasets - Curated Collections

Curated collections of related security datasets for comprehensive testing and training.

## Available Collections

| Meta-Dataset | Datasets | MITRE Techniques | Description |
|-------------|----------|------------------|-------------|
| [ransomware-suite](ransomware-suite/) | 7 | T1486, T1490, T1489 | Ransomware detection (Ryuk, Clop, etc.) |
| [credential-dumping-t1003](credential-dumping-t1003/) | 7 | T1003.001-.003 | Credential theft (LSASS, Mimikatz, NTDS) |
| [aws-cloud-attacks](aws-cloud-attacks/) | 8 | T1078, T1098, T1485 | AWS security threats |
| [lateral-movement-suite](lateral-movement-suite/) | 7 | T1021, T1047 | Network propagation (RDP, PsExec, WMI) |
| [web-exploitation-cves](web-exploitation-cves/) | 8 | T1190, T1210 | Critical CVEs (Log4Shell, Spring4Shell) |
| [top-10-mitre-attacks](top-10-mitre-attacks/) | 10 | 10 techniques | Essential SOC detections |
| [sample-logs](sample-logs/) | - | - | Small sample data for testing |

**Total: 47 dataset dependencies across 6 curated collections**

## Usage

```bash
# Replay an entire attack collection
echolake replay \
  --dataset github:daveherrald/echolake-datasets/meta/ransomware-suite \
  --output ./replayed-attacks

# Replay top 10 essential detections
echolake replay \
  --dataset github:daveherrald/echolake-datasets/meta/top-10-mitre-attacks \
  --output ./replayed-attacks
```

## How It Works

Meta-datasets use the dependency system to bundle related datasets:

```yaml
dependencies:
  - dataset: "github:daveherrald/echolake-datasets/splunk/access-lsass-memory-for-dump-creation"
    version: "*"
    description: "LSASS memory dumping detection"
```

When you replay a meta-dataset, EchoLake resolves all dependencies, downloads data as needed, and replays everything with consistent timestamp manipulation.
