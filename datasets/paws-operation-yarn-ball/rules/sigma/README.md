# Operation Yarn Ball detection rules (Sigma)

Sample [Sigma](https://sigmahq.io/) rules for the scripted intrusion prelude in
this dataset. They are starting points for detection engineering against the
evidenced behaviors, not tuned production content. Each one matches records
present in this dataset's logs, passes `sigma check`, and converts to Splunk,
Loki, and Lucene (see [`conversions.md`](conversions.md)). The rules are ordered
to follow the scripted sequence.

The rule set deliberately stops at what the telemetry evidences. The capture
has no execution evidence for credential dumping, lateral movement, bulk
encryption, or event-log clearing (see the dataset
[`README.md`](../../README.md)), so there are no rules for those stages. The
recurring port 8080 traffic to the lab segment is also not flagged: the capture
attributes it to a Python service on PAWS-DC01, not to this intrusion.

| Rule | Detects | Log | Level | ATT&CK |
|------|---------|-----|-------|--------|
| [defender_exclusion_temp_and_patch](paws_defender_exclusion_temp_and_patch.yml) | The `Add-MpPreference` script block excluding `C:\Windows\Temp` and `patch-kb5041234.exe` from Defender, the first scripted action | [`powershell.xml.gz`](../../data/powershell.xml.gz) (script block logging) | high | [T1685](https://attack.mitre.org/techniques/T1685/) |
| [agent_sim_launch_from_public](paws_agent_sim_launch_from_public.yml) | `node.exe` executing `openclaw_sim.js` out of `C:\Users\Public`, the agentic foothold all later commands descend from | [`sysmon.xml.gz`](../../data/sysmon.xml.gz) + [`security.xml.gz`](../../data/security.xml.gz) (process creation) | high | [T1059.007](https://attack.mitre.org/techniques/T1059/007/) |
| [agent_discovery_burst](paws_agent_discovery_burst.yml) | The seven-command discovery burst (`whoami`, `hostname`, `ipconfig`, `systeminfo`, `net user`, `net group`, `net view`) run by `node.exe` children | [`sysmon.xml.gz`](../../data/sysmon.xml.gz) (process creation) | medium | [T1082](https://attack.mitre.org/techniques/T1082/), [T1016](https://attack.mitre.org/techniques/T1016/), [T1033](https://attack.mitre.org/techniques/T1033/), [T1087.001](https://attack.mitre.org/techniques/T1087/001/), [T1069.002](https://attack.mitre.org/techniques/T1069/002/), [T1018](https://attack.mitre.org/techniques/T1018/) |
| [agent_lab_domain_contact](paws_agent_lab_domain_contact.yml) | The curl commands against `yarn-ball.xyz`: the diagnostics POST and the patch-binary retrieval | [`sysmon.xml.gz`](../../data/sysmon.xml.gz) + [`security.xml.gz`](../../data/security.xml.gz) (process creation) | high | [T1071.001](https://attack.mitre.org/techniques/T1071/001/), [T1105](https://attack.mitre.org/techniques/T1105/) |
| [windowsupdate_scheduled_task](paws_windowsupdate_scheduled_task.yml) | The `SecurityPatchRecovery` task created under `Microsoft\Windows\WindowsUpdate\` to run the temp-staged binary at logon with HIGHEST privileges | [`sysmon.xml.gz`](../../data/sysmon.xml.gz) + [`security.xml.gz`](../../data/security.xml.gz) (process creation) | high | [T1053.005](https://attack.mitre.org/techniques/T1053/005/), [T1036.004](https://attack.mitre.org/techniques/T1036/004/) |
| [staged_patch_binary_execution](paws_staged_patch_binary_execution.yml) | `patch-kb5041234.exe` executing from `C:\Windows\Temp`, the final scripted action, whose name impersonates a Windows update patch | [`sysmon.xml.gz`](../../data/sysmon.xml.gz) + [`security.xml.gz`](../../data/security.xml.gz) (process creation) | high | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) |
| [outbound_lab_host_9090](paws_outbound_lab_host_9090.yml) | The single outbound `powershell.exe` TCP connection, PAWS-WS02 to the lab host on port 9090, which returns roughly 327 KB | [`zeek_conn.jsonl.gz`](../../data/zeek_conn.jsonl.gz) | medium | [T1105](https://attack.mitre.org/techniques/T1105/) |

## Verification

Every rule was checked with `sigma check` (0 errors, 0 issues), counted against
the dataset, and converted to all three backends. The match count is the number
of dataset records that satisfy the rule's full condition across both
process-creation sources where the selection applies: Sysmon Event ID 1 and
Security Event ID 4688 both record process creation, so one action can be
counted in both. Parent-image selections match Sysmon only, because the
Security 4688 records carry no parent image; the `node.exe` discovery rule is
therefore Sysmon-only. Each curl transfer crosses a three-process chain
(`node.exe` -> `cmd.exe` -> `cmd.exe` -> `curl.exe`), so the two transfers
produce thirteen process-creation records.

| Rule | `sigma check` | Dataset matches | Splunk | Loki | Lucene |
|------|:---:|:---:|:---:|:---:|:---:|
| defender_exclusion_temp_and_patch | pass | 3 | yes | yes | yes |
| agent_sim_launch_from_public | pass | 4 | yes | yes | yes |
| agent_discovery_burst | pass | 14 | yes | yes | yes |
| agent_lab_domain_contact | pass | 13 | yes | yes | yes |
| windowsupdate_scheduled_task | pass | 2 | yes | yes | yes |
| staged_patch_binary_execution | pass | 2 | yes | yes | yes |
| outbound_lab_host_9090 | pass | 1 | yes | yes | yes |

Converted queries are in [`conversions.md`](conversions.md). The Splunk and
Lucene conversions use
[`pipelines/paws_logsources.yml`](pipelines/paws_logsources.yml), which maps
the Windows and Zeek logsources to `source=` filters; Loki needs no pipeline.
The standard pySigma windows and sysmon pipelines can be used instead. Replace
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

- **Field names are the parsed representation.** The Windows rules use Sysmon
  and Security field names (`Image`, `ParentImage`, `CommandLine`,
  `ScriptBlockText`, `NewProcessName`); the Zeek rule uses `id.resp_p`. Map
  them to your own pipeline's field names before deploying.
- **ATT&CK tags were validated against ATT&CK v20.0**, the version pySigma
  1.5.1's live STIX download serves at check time. v20 renumbered the
  Impair Defenses family, so the Defender-exclusion rule is tagged
  `attack.t1685` (Disable or Modify Tools); earlier ATT&CK versions carried
  this as `T1562.001`. The tactic shortnames follow the v18-and-later
  renames: `attack.stealth` (masquerade rules) and
  `attack.defense-impairment` (the exclusion rule).
- **Two tagged behaviors sit just outside the dataset README's evidenced
  ATT&CK table.** The scheduled-task and staged-binary rules carry
  masquerade tags (T1036.004 for the WindowsUpdate-named task, T1036.005 for
  the patch-named binary in Temp), and the domain-contact and 9090 rules
  carry command-and-control tags (T1071.001, T1105). The behaviors are
  present in the telemetry; the dataset README's table lists only the
  execution, persistence, privilege-escalation, defense-evasion, and
  discovery coverage, so the extra tags are noted here rather than silently
  assumed.
- **The yarn-ball.xyz contacts are attempts.** No DNS resolution or HTTP
  session for the domain appears in the network telemetry, so command lines
  are the only place the signal exists. The 9090 connection did transfer
  data (roughly 327 KB returned to the workstation).
- **The QEMU guest-agent staging is intentionally not detected.** The
  capture's scenario files are staged by `qemu-ga.exe` -> `gspawn-win64-helper.exe`
  -> `powershell` chains. That is simulation-harness machinery, not intrusion
  behavior, so a rule on it would fire on the lab's own tooling.
- **These are samples.** Tune thresholds and false positives for your
  environment. The highest-fidelity signals here are the Defender exclusions,
  the WindowsUpdate-named task, and the temp-staged patch binary.
