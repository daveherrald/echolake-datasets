# cloud-data-exfiltration detection rules (Sigma)

A single entry-point [Sigma](https://sigmahq.io/) rule for this dataset: the GitHub
secret-scanning alert for the leaked SSH private key, the first signal of the
exfiltration chain and the opening stage of the Attack Flow bundle. It is a
starting point for detection engineering against the scenario, not tuned
production content. The rule matches records present in this dataset's logs,
passes `sigma check`, and converts to Splunk, Loki, and Lucene (see
[`conversions.md`](conversions.md)).

| Rule | Detects | Log | Level | ATT&CK |
|------|---------|-----|-------|--------|
| [github_leaked_ssh_key_alert](cloudexfil_github_leaked_ssh_key_alert.yml) | GitHub secret scanning raising an alert for a pushed SSH private key | [`github_audit`](../../data/github_audit.jsonl.gz) | high | [T1552.004](https://attack.mitre.org/techniques/T1552/004/) |

The remaining stages of the chain (the SSH use of the leaked key, the IMDS
credential theft, the training-bucket reads, the SFTP pull, the VPC egress) are
investigation material for the hunt once this rule fires, not additional rules;
correlating them is the exercise.

## Verification

The rule was checked with `sigma check` (0 errors, 0 issues), counted against the
dataset, and converted to all three backends. The match count is the number of
dataset records that satisfy the rule's full condition.

| Rule | `sigma check` | Dataset matches | Splunk | Loki | Lucene |
|------|:---:|:---:|:---:|:---:|:---:|
| github_leaked_ssh_key_alert | pass | 1 | yes | yes | yes |

Converted queries are in [`conversions.md`](conversions.md). The Splunk and Lucene
conversions use [`pipelines/cloudexfil_logsources.yml`](pipelines/cloudexfil_logsources.yml),
which maps each logsource to its `source=` sourcetype; Loki needs no pipeline. Replace the
sources with your own index or sourcetype.

Toolchain used for verification:

| Tool | Version |
|------|---------|
| sigma-cli | 3.1.0 |
| pySigma | 1.5.1 |
| pysigma-backend-splunk (Splunk) | 2.1.0 |
| pysigma-backend-elasticsearch (Lucene) | 2.1.1 |
| pysigma-backend-loki | 0.15.1 |
