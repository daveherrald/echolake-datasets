# Cloud Data Exfiltration

A developer pushes an SSH private key to GitHub. Five minutes later, someone else uses that key to log into the developer's EC2 host, steals the instance role's credentials from the metadata service, and takes a bucket of ML training data over SFTP. The developer closes the secret-scanning alert and pushes a fix, and neither step revokes anything. This dataset holds the telemetry for all of it, plus three days of the account's ordinary background, as replayable logs for detection engineering, threat hunting and SOC investigation training.

The scenario is built around one judgment: is the secret-scanning alert closed, or is the incident? Answering it means following the key from GitHub to the host, and the instance role from the host to CloudTrail.

## What it is

- **348,963 events** across 5 data sources, 2026-10-11 01:00 to 2026-10-14 00:00 UTC (71 hours)
- **One victim host**, an Ubuntu EC2 instance with a CrowdStrike Falcon sensor, whose instance role can read an S3 training-data bucket
- **Background** is real account traffic: a SaaS application's own Lambda and ECS infrastructure, daily audit scanners, internet SSH brute force against the host, and GitHub activity across four organizations
- **The developer's own work sessions are in the lead-in**, from his usual IP, and the intrusion begins three minutes after his last one ends
- **Attack** runs 18:50 to 19:47 UTC on 2026-10-13, and no source shows any attacker activity before the key leak

## Scenario

The fictional ML company Acme Research keeps its training data in S3 and gives developers EC2 boxes with read access to it. Developer `s.onarake` works on `acme-platform/datalake-utils` from the host a few hours a day, from 75.125.237.59, pushing over SSH.

On 2026-10-12 he copies his own `~/.ssh/id_rsa` into `training/fixtures/` as a test fixture for the tokenizer suite and leaves it untracked. On 2026-10-13, in a session that starts at 18:28, he runs the test suite, does `git add training/`, and pushes at 18:50:14, committing the fixture along with the configs. GitHub secret scanning creates an `ssh_private_key` alert at 18:52:41. He checks the push and disconnects at 18:52.

At 18:55:44 an outside address, 54.193.215.120, logs in as `s.onarake` with the same key fingerprint. Over the next twelve minutes the intruder runs host discovery, requests an IMDSv2 token, pulls the instance role credentials from the metadata service, enumerates IAM and S3 as `model-dev-05-readonly`, syncs 65 objects from `jn-model-training-data-5233` onto the host, and opens a second key login at 19:07 to SFTP the data out, 507 MB in seven files, before vanishing at 19:08.

At 19:22:46 `s.onarake` resolves the alert. In a new session (19:20 to 19:49) he removes the file from the repository, pushes at 19:25:16 and 19:42:12, and fetches at 19:46:27. Nothing in the data touches `authorized_keys` or the stolen role credentials, and the public exposure window for the key runs from 18:50:14 to 19:42:12.

## Timeline

All times are original capture times on 2026-10-13 UTC unless noted. EchoLake shifts them on replay. The Flow column matches the action IDs in `attack_flow.json`.

| Flow | Time | Event | Evidence | ATT&CK |
|---|------|-------|----------|--------|
| - | Oct 12, 14:40 | `cp /home/s.onarake/.ssh/id_rsa training/fixtures/sample.bin`, left untracked | crowdstrike_fdr | T1552.004 |
| S1 | 18:50:14 | `git push origin main` from the host leaks the fixture. Secret scanning alerts at 18:52:41. | github_audit, crowdstrike_fdr | T1552.004 |
| S2 | 18:55:44 | Publickey SSH login as `s.onarake` from 54.193.215.120, an IP never used by this account, same key fingerprint | linux_auth, aws_vpc_flow | T1078, T1021.004 |
| S3 | 18:56:42 | `id`, `hostname`, `uname -a`, `ls -la ~` | crowdstrike_fdr | T1082, T1033 |
| S4 | 18:58:12 | IMDSv2 token request, then instance role credentials from 169.254.169.254 | crowdstrike_fdr | T1552.005 |
| S5 | 18:59:23 to 19:00:48 | `sts get-caller-identity`, `s3 ls`, IAM role and policy enumeration, a denied `ec2 describe-instances`, all as `model-dev-05-readonly` from the instance IP 13.57.16.209 | aws_cloudtrail, crowdstrike_fdr | T1078.004, T1087.004, T1619 |
| S6 | 19:02:43 to 19:04:45 | List, then `aws s3 sync` of `jn-model-training-data-5233` into `~/data`: 65 GetObject calls, about 514 MB of S3 ingress | aws_cloudtrail, aws_vpc_flow, crowdstrike_fdr | T1530, T1074.001 |
| S7 | 19:07:42 to 19:07:46 | Second key login opens SFTP and reads 7 files (507 MB). 526 MB egresses to 54.193.215.120. | linux_auth, aws_vpc_flow | T1048.002 |
| S8 | 19:22:46 to 19:46:27 | `s.onarake` resolves the alert, then removes the file and pushes twice from the host. The key stays valid. | github_audit, crowdstrike_fdr | n/a |

`attack_flow.json` encodes S1 through S8 as a MITRE Attack Flow 2.0 (STIX 2.1) bundle. The Oct 12 fixture copy sits outside the flow, before the leak.

## Environment

- **Cloud:** AWS, us-west-1. The account runs a SaaS application's infrastructure (Lambda, ECS, Firehose, Batch) plus AWS Config, Trusted Advisor and Macie.
- **Victim host:** `ip-172-31-24-50` (`i-0712927224ce899b4`), Ubuntu, CrowdStrike Falcon sensor, auth.log shipped by Fluent Bit, instance role `model-dev-05-readonly` with read access to `jn-model-training-data-5233`.
- **GitHub:** four organizations (`acme-research`, `acme-platform`, `acme-quant`, `acme-infra`) under the business `acme-research-llc`. The scenario repository is `acme-platform/datalake-utils`, public.
- **People:** `s.onarake` works from 75.125.237.59. The intrusion comes from 54.193.215.120, an AWS EC2 address.

## Data Sources

| File | [Echolake Sourcetype](https://github.com/daveherrald/echolake/blob/main/src/echolake/inputs/timestamp_registry.yaml) | Events | Description |
|------|------------|-------:|-------------|
| `data/aws_cloudtrail.jsonl.gz` | `aws:cloudtrail` | 261,801 | Management and S3 data events for the account. Time field `eventTime`. |
| `data/aws_vpc_flow.jsonl.gz` | `aws:vpcflow:json` | 73,752 | Flow records for the victim interface, one JSON object per record. Time fields `start` and `end`, epoch seconds. |
| `data/crowdstrike_fdr.jsonl.gz` | `crowdstrike:fdr` | 12,293 | Falcon Data Replicator events from the victim host, plus Falcon API audit events. Time field `timestamp`, an epoch-ms string for sensor events and ISO8601 for audit events. |
| `data/linux_auth.jsonl.gz` | `linux_secure:fluentbit` | 887 | `/var/log/auth.log` from the victim host. The syslog line is in `message`, and its RFC3339 prefix is the event time. |
| `data/github_audit.jsonl.gz` | `github:audit` | 230 | Organization audit log across the four orgs. Time fields `timestamp` and `created_at`, epoch ms. |

Every line is the original JSON record as the source produced it, with no envelope, and each file is sorted by event time.

The sourcetype is the key EchoLake uses to find each source's time fields, defined in its [timestamp registry](https://github.com/daveherrald/echolake/blob/main/src/echolake/inputs/timestamp_registry.yaml). Replaying this dataset needs an echolake build that includes the four entries added for it; older builds stop at timestamp extraction rather than emit unshifted events.

## Background

The haystack the needle sits in:

- A SaaS application's own infrastructure runs continuously in the account: dozens of Lambda functions, ECS services and Batch jobs on hourly cycles, plus STS session refreshes carrying expired session tokens, which is normal CloudTrail.
- Daily audit-scanner sweeps enumerate every IAM role, policy and bucket, including the victim role and the training-data bucket.
- The host faces the internet: SSH pre-auth failures, connection penalties and brute-force bursts from scanning addresses, and VPC REJECT records for the rest.
- GitHub shows 25 to 31 actors a day across the four organizations: clones, pushes, fetches, pull requests.
- Eight other secret-scanning alerts fire across the orgs in the window, on other repos and other actors, including two other `ssh_private_key` alerts. One of those is resolved by `f.santos` at 09:15 UTC on 2026-10-13, ten hours before the scenario alert.
- The developer's own working sessions: five SSH sessions across the three days, with git, python and pytest activity that lines up with his GitHub audit events.

## MITRE ATT&CK Coverage

| Tactic | Techniques |
|--------|------------|
| Initial Access | T1078, T1078.004 |
| Credential Access | T1552.004, T1552.005 |
| Lateral Movement | T1021.004 |
| Discovery | T1082, T1033, T1087.004, T1619 |
| Collection | T1530, T1074.001 |
| Exfiltration | T1048.002 |

## Investigation Notes

- **The IP is the pivot, not the key.** The account's legitimate sessions, including one that ends at 18:52 on 2026-10-13, all come from 75.125.237.59 with the same key fingerprint the intruder uses at 18:55. Same credential, new source address.
- **The leaked key has a visible origin.** The Oct 12 14:40 `cp` into `training/fixtures/` and the 18:50:14 push from the host reconstruct exactly how the key reached a public repository.
- **The alert is not the only alert.** Nine secret-scanning events exist in the window. The scenario one is the only `ssh_private_key` alert on `datalake-utils`; confirming which repository, which actor and which push requires reading the audit rows, not just the alert type.
- **Genuine background looks suspicious too.** The audit scanners call Get/List on the victim role and the training-data bucket every day. Separating that from S5 depends on the principal and the source IP.
- Each SSH login on the host produces FDR `CriticalFileAccessed` events on `/etc/shadow` alongside `unix_chkpwd`. That is the PAM password-expiry check, not credential dumping.
- The three exfiltration figures measure different things. 507 MB is file bytes read by sftp-server, 526 MB is flow-log egress with protocol overhead, and about 514 MB is S3 ingress to the host.
- GitHub audit events carry no `transport` field, so git operations over SSH and HTTPS look the same.

## Known Limitations

- The victim role first appears in CloudTrail at 2026-10-12 22:31 UTC, through Config and audit-scanner reads, and the event that created it is not in the data.
- The host rebooted at 2026-10-13 04:07 UTC, and nothing in the data shows what started the reboot.
- GitHub has eight overnight hours with no audit events, normal for the org's activity pattern but worth knowing when checking continuity.
- Only top-level time fields are shifted on replay. Times nested inside CloudTrail objects (for example `userIdentity.sessionContext.attributes.creationDate` and `responseElements.credentials.expiration`) and inside the FDR audit `Extensions` list keep their capture-time values.

## How This Dataset Was Built

The logs were captured in an isolated lab AWS account. The intrusion was scripted, and the developer's lead-in sessions were synthesized to complete the persona, timed to line up with his GitHub audit events. Real binary hashes from the host were reused for the process telemetry where available.

Before release, identifying values were replaced: person, company, product and account names became fictional ones, AWS account IDs became 11-digit values that cannot match any real account (including inside session tokens, which were re-encoded), and third-party secrets were removed. A decode-everything audit confirms no real account ID survives in plain text or in base64.

`dataset.yaml` carries per-file event counts and sourcetypes, and was verified by replaying the full dataset: 348,963 events processed, zero errors, every time field moved by an identical delta with no type changes.

## Replay

```bash
echolake echo --dataset local:./cloud-data-exfiltration --output ./echoed
```

`dataset.yaml` uses `schema: raw` with a per-file `sourcetype`, so EchoLake finds and shifts each source's native time fields. Each field keeps its original type and format, for example epoch-ms integers in GitHub and epoch-second strings in FDR. With the default `prevent_future: true`, the last event lands at the time of the run.

EchoLake applies the future ceiling to each time field on its own, not to each event. Fields meant to point past the event get pinned to the run time: in this dataset that is 4 GitHub token `expires_at` values and 9 VPC `end` values that round past the last `start`. One EchoLake quirk to know: the echoed output files are named `.jsonl.gz` but written uncompressed.

## License

CC0 1.0 Universal (Public Domain Dedication). See [LICENSE](../../LICENSE).
