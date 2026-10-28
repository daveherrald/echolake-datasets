# cloud-data-exfiltration detection rules (Sigma)

Sample [Sigma](https://sigmahq.io/) rules for the signals in this dataset. They are
starting points for detection engineering against the leaked-key cloud exfiltration
scenario, not tuned production content. Each one matches records present in this
dataset's logs, passes `sigma check`, and converts to Splunk, Loki, and Lucene (see
[`conversions.md`](conversions.md)).

| Rule | Detects | Log | Level | ATT&CK |
|------|---------|-----|-------|--------|
| [github_leaked_ssh_key_alert](cloudexfil_github_leaked_ssh_key_alert.yml) | GitHub secret scanning raising an alert for a pushed SSH private key | [`github_audit`](../../data/github_audit.jsonl.gz) | high | [T1552.004](https://attack.mitre.org/techniques/T1552/004/) |
| [ssh_login_from_intruder_ip](cloudexfil_ssh_login_from_intruder_ip.yml) | Any OpenSSH auth record referencing the intruder address (threat-intel seed) | [`linux_auth`](../../data/linux_auth.jsonl.gz) | medium | [T1078](https://attack.mitre.org/techniques/T1078/), [T1021.004](https://attack.mitre.org/techniques/T1021/004/) |
| [imdsv2_credential_theft](cloudexfil_imdsv2_credential_theft.yml) | A shell command reaching the IMDS address `169.254.169.254` to steal instance-role credentials | [`crowdstrike_fdr`](../../data/crowdstrike_fdr.jsonl.gz) | high | [T1552.005](https://attack.mitre.org/techniques/T1552/005/) |
| [s3_training_bucket_mass_read](cloudexfil_s3_training_bucket_mass_read.yml) | Reads (GetObject, ListObjects, HeadObject) of the ML training-data bucket in CloudTrail | [`aws_cloudtrail`](../../data/aws_cloudtrail.jsonl.gz) | high | [T1530](https://attack.mitre.org/techniques/T1530/) |
| [sftp_bulk_file_read](cloudexfil_sftp_bulk_file_read.yml) | `sftp-server` opening files for reading, the exfiltration channel off the host | [`linux_auth`](../../data/linux_auth.jsonl.gz) | high | [T1048.002](https://attack.mitre.org/techniques/T1048/002/), [T1005](https://attack.mitre.org/techniques/T1005/) |
| [vpcflow_exfil_to_intruder_ip](cloudexfil_vpcflow_exfil_to_intruder_ip.yml) | VPC flow egress to the intruder address (threat-intel seed) | [`aws_vpc_flow`](../../data/aws_vpc_flow.jsonl.gz) | medium | [T1048](https://attack.mitre.org/techniques/T1048/) |
| [github_secret_alert_resolved_wontfix](cloudexfil_github_secret_alert_resolved_wontfix.yml) | A secret-scanning alert closed as `wont_fix` without rotating the exposed credential | [`github_audit`](../../data/github_audit.jsonl.gz) | medium | [T1078](https://attack.mitre.org/techniques/T1078/) |

The `github_leaked_ssh_key_alert` and `sftp_bulk_file_read` rules are the two referenced
from the dataset's Attack Flow bundle (as `sigma-rule` external references on the matching
attack-action); the others are additional coverage across the kill chain.

## Verification

Every rule was checked with `sigma check` (0 errors, 0 issues), counted against the
dataset, and converted to all three backends. The match count is the number of dataset
records that satisfy the rule's full condition.

| Rule | `sigma check` | Dataset matches | Splunk | Loki | Lucene |
|------|:---:|:---:|:---:|:---:|:---:|
| github_leaked_ssh_key_alert | pass | 2 | yes | yes | yes |
| ssh_login_from_intruder_ip | pass | 8 | yes | yes | yes |
| imdsv2_credential_theft | pass | 9 | yes | yes | yes |
| s3_training_bucket_mass_read | pass | 71 | yes | yes | yes |
| sftp_bulk_file_read | pass | 7 | yes | yes | yes |
| vpcflow_exfil_to_intruder_ip | pass | 9 | yes | yes | yes |
| github_secret_alert_resolved_wontfix | pass | 2 | yes | yes | yes |

Converted queries are in [`conversions.md`](conversions.md). The Splunk and Lucene
conversions use [`pipelines/cloudexfil_logsources.yml`](pipelines/cloudexfil_logsources.yml),
which maps each logsource to its `source=` sourcetype; Loki needs no pipeline. Replace the
sources with your own index or sourcetype.

Toolchain used for verification:

| Tool | Version |
|------|---------|
| sigma-cli | 3.1.0 |
| pySigma | 1.5.1 |
| pysigma-backend-splunk | 2.1.0 |
| pysigma-backend-elasticsearch (Lucene) | 2.1.1 |
| pysigma-backend-loki | 0.15.1 |

## Notes

- **Field names are the parsed representation.** CloudTrail keeps its native keys
  (`eventName`, `requestParameters.bucketName`); GitHub audit fields are flat (`action`,
  `secret_type`, `resolution`); the Linux OpenSSH source carries one `message` field;
  CrowdStrike FDR uses `CommandLine`; VPC flow uses `dstaddr`. Map them to your pipeline's
  field names before deploying.
- **Two fields differ from the scenario's earlier shorthand.** The Linux source has no
  `program` field, so the SFTP rule keys on `message` containing `sftp-server[` and
  `flags READ` rather than a program name; GitHub's `secret_type` is a top-level field,
  not `alert.secret_type`.
- **`GetCallerIdentity` is not used as a rule.** The assumed-role `GetCallerIdentity` call
  appears about 3,400 times across this window, so it is not a usable discriminator on its
  own; the collection signal is the read burst against the named training-data bucket.
- **Two rules are threat-intel seeds.** `ssh_login_from_intruder_ip` and
  `vpcflow_exfil_to_intruder_ip` match a point-in-time address; replace it with your own
  indicator and expect it to age out.
- **These are samples.** Tune thresholds and false positives for your environment. The
  highest-fidelity signals are the SSH-key secret-scanning alert, the IMDS access from a
  shell, and the mass read of the named training-data bucket.
