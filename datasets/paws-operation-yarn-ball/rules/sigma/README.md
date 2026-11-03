# Operation Yarn Ball detection rules (Sigma)

A single entry-point [Sigma](https://sigmahq.io/) rule for this dataset: the
PowerShell script block that sets Defender exclusions for the staging
directory and the patch binary, the first scripted action of the intrusion
prelude and the moment the target host loses its safety net. It is a starting
point for detection engineering, not tuned production content. The rule matches
records present in this dataset's logs, passes `sigma check`, and converts to
Splunk, Loki, and Lucene (see [`conversions.md`](conversions.md)).

The rest of the scripted prelude (the agent simulation launches, the discovery
burst, the lab-domain contacts, the scheduled task, the staged binary, the
outbound 9090 connection) is investigation material for the hunt once this rule
fires, not additional rules. The capture's own README bounds what the telemetry
evidences, and the recurring port 8080 traffic is deliberately not flagged: the
capture attributes it to a Python service on PAWS-DC01.

| Rule | Detects | Log | Level | ATT&CK |
|------|---------|-----|-------|--------|
| [defender_exclusion_temp_and_patch](paws_defender_exclusion_temp_and_patch.yml) | The `Add-MpPreference` script block excluding `C:\Windows\Temp` and `patch-kb5041234.exe` from Defender | [`powershell.xml.gz`](../../data/powershell.xml.gz) (script block logging) | high | [T1685](https://attack.mitre.org/techniques/T1685/) |

## Verification

The rule was checked with `sigma check` (0 errors, 0 issues), counted against
the dataset, and converted to all three backends. The match count is the
number of dataset records that satisfy the rule's full condition.

| Rule | `sigma check` | Dataset matches | Splunk | Loki | Lucene |
|------|:---:|:---:|:---:|:---:|:---:|
| defender_exclusion_temp_and_patch | pass | 3 | yes | yes | yes |

Converted queries are in [`conversions.md`](conversions.md). The Splunk and
Lucene conversions use
[`pipelines/paws_logsources.yml`](pipelines/paws_logsources.yml), which maps
the PowerShell script-block logsource to a `source=` filter; Loki needs no
pipeline. The standard pySigma windows pipelines can be used instead. Replace
the sources with your own index or sourcetype.

Toolchain used for verification:

| Tool | Version |
|------|---------|
| sigma-cli | 3.1.0 |
| pySigma | 1.5.1 |
| pysigma-backend-splunk (Splunk) | 2.1.0 |
| pysigma-backend-elasticsearch (Lucene) | 2.1.1 |
| pysigma-backend-loki | 0.15.1 |

## Notes

- **Field names are the parsed representation.** The rule uses the PowerShell
  operational channel's `ScriptBlockText`; map it to your own pipeline's field
  names before deploying.
- **ATT&CK tags were validated against ATT&CK v20.0**, the version pySigma
  1.5.1's live STIX download serves at check time. v20 renumbered the Impair
  Defenses family, so the rule is tagged `attack.t1685` (Disable or Modify
  Tools); earlier ATT&CK versions carried this as `T1562.001`.
- **These are samples.** Tune thresholds and false positives for your
  environment. The exclusion is the entry point; what runs from the excluded
  paths afterward is the hunt.
