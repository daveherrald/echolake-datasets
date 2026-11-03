# Operation Black Start detection rules (Sigma)

A single entry-point [Sigma](https://sigmahq.io/) rule for this dataset: the
outbound connection to a publicly documented Cobalt Strike C2 indicator, the
built-in threat-intel hook the scenario was built to fire on replay. It is a
starting point for detection engineering against the Operation Black Start
kill chain, not tuned production content. The rule matches records present in
this dataset's logs, passes `sigma check`, and converts to Splunk, Loki, and
Lucene (see [`conversions.md`](conversions.md)).

The rest of the kill chain (the agentic shell spawn, the recon burst, the
LSASS read, the IT-to-OT pivot, the OT reads, the log clears) is investigation
material for the hunt once this rule fires, not additional rules; correlating
the stages from the beacon is the exercise.

| Rule | Detects | Log | Level | ATT&CK |
|------|---------|-----|-------|--------|
| [c2_indicator_outbound](currentis_c2_indicator_outbound.yml) | Any outbound connection to the documented C2 indicator `121.43.243.13` (the threat-intel seed) | [`zeek_conn`](../../data/zeek_conn.jsonl.gz) | medium | [T1071.001](https://attack.mitre.org/techniques/T1071/001/), [T1041](https://attack.mitre.org/techniques/T1041/) |

## Verification

The rule was checked with `sigma check` (0 errors, 0 issues), counted against
the dataset, and converted to all three backends. The match count is the number
of dataset records that satisfy the rule's full condition.

| Rule | `sigma check` | Dataset matches | Splunk | Loki | Lucene |
|------|:---:|:---:|:---:|:---:|:---:|
| c2_indicator_outbound | pass | 38 | yes | yes | yes |

Converted queries are in [`conversions.md`](conversions.md). The Splunk and
Lucene conversions use
[`pipelines/currentis_logsources.yml`](pipelines/currentis_logsources.yml),
which maps the Zeek logsource to a `source=` filter; Loki needs no pipeline.
The standard pySigma zeek pipelines can be used instead. Replace the sources
with your own index or sourcetype.

Toolchain used for verification:

| Tool | Version |
|------|---------|
| sigma-cli | 3.1.0 |
| pySigma | 1.5.1 |
| pysigma-backend-splunk (Splunk) | 2.1.0 |
| pysigma-backend-elasticsearch (Lucene) | 2.1.1 |
| pysigma-backend-loki | 0.15.1 |

## Notes

- **Field names are the parsed representation.** The Zeek rule uses
  `id.resp_h`; map it to your own pipeline's field names before deploying.
- **The threat-intel rule ages out.** The rule matches a specific IP that was a
  documented C2 indicator at build time. Confirm it is still listed before
  alerting in production, and treat a match as a pivot, not a verdict.
- **These are samples.** Tune thresholds and false positives for your
  environment. The rule is the entry point; the chain behind it is the hunt.
