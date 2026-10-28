# Operation Black Start detection rules (Sigma)

Sample [Sigma](https://sigmahq.io/) rules for the signals in this dataset. They are
starting points for detection engineering and SOC-investigation training against the
Operation Black Start kill chain, not tuned production content. Each one matches
records present in this dataset's logs, passes `sigma check`, and converts to Splunk,
Loki, and Lucene (see [`conversions.md`](conversions.md)). The rules are ordered to
follow the kill chain.

| Rule | Detects | Log | Level | ATT&CK |
|------|---------|-----|-------|--------|
| [agentic_ai_shell_spawn](currentis_agentic_ai_shell_spawn.yml) | The OpenClaw AI assistant (`node.exe`) spawning PowerShell or cmd, the stage-0 prompt-injection foothold | [`microsoft_winevtlog`](../../data/microsoft_winevtlog.xml.gz) (process creation) | high | [T1566](https://attack.mitre.org/techniques/T1566/), [T1059.001](https://attack.mitre.org/techniques/T1059/001/) |
| [lotl_domain_recon](currentis_lotl_domain_recon.yml) | The living-off-the-land AD recon burst, including the account-specific `helixgrid-svc /domain` lookup | [`microsoft_winevtlog`](../../data/microsoft_winevtlog.xml.gz) (process creation) | medium | [T1087.002](https://attack.mitre.org/techniques/T1087/002/), [T1482](https://attack.mitre.org/techniques/T1482/), [T1069.002](https://attack.mitre.org/techniques/T1069/002/), [T1018](https://attack.mitre.org/techniques/T1018/), [T1033](https://attack.mitre.org/techniques/T1033/) |
| [masqueraded_update_binary](currentis_masqueraded_update_binary.yml) | `kb5041234-v3.exe` running from `C:\Users\Public`, the implant posing as a Windows update | [`microsoft_winevtlog`](../../data/microsoft_winevtlog.xml.gz) (process creation) | high | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) |
| [c2_beacon_user_agent](currentis_c2_beacon_user_agent.yml) | The Sliver HTTP beacon by its hardcoded Chrome 106 User-Agent to the C2 address | [`zeek_http`](../../data/zeek_http.jsonl.gz) | high | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) |
| [c2_indicator_outbound](currentis_c2_indicator_outbound.yml) | Any outbound connection to the documented C2 indicator `121.43.243.13` (the threat-intel seed) | [`zeek_conn`](../../data/zeek_conn.jsonl.gz) | medium | [T1071.001](https://attack.mitre.org/techniques/T1071/001/), [T1041](https://attack.mitre.org/techniques/T1041/) |
| [run_key_persistence](currentis_run_key_persistence.yml) | The `CLIENTSYNC` Run key launching `clientsync.ps1`, the implant's logon persistence | [`microsoft_winevtlog`](../../data/microsoft_winevtlog.xml.gz) (Sysmon registry) | medium | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) |
| [lsass_access_masqueraded_binary](currentis_lsass_access_masqueraded_binary.yml) | The LSASS read by `kb5041234-v3.exe` that harvests the cached vendor credential | [`microsoft_winevtlog`](../../data/microsoft_winevtlog.xml.gz) (Sysmon process access) | high | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) |
| [vendor_credential_cmdkey_rdp](currentis_vendor_credential_cmdkey_rdp.yml) | `cmdkey` staging the stolen `helixgrid-svc` credential for a TERMSRV (RDP) session | [`microsoft_winevtlog`](../../data/microsoft_winevtlog.xml.gz) (process creation) | high | [T1021.001](https://attack.mitre.org/techniques/T1021/001/), [T1078](https://attack.mitre.org/techniques/T1078/) |
| [vendor_account_rdp_logon_ot](currentis_vendor_account_rdp_logon_ot.yml) | The interactive (type 10) RDP logon by `helixgrid-svc` onto the OT jump host | [`microsoft_winevtlog`](../../data/microsoft_winevtlog.xml.gz) (Security 4624) | high | [T1021.001](https://attack.mitre.org/techniques/T1021/001/), [T1078](https://attack.mitre.org/techniques/T1078/) |
| [ot_config_file_access](currentis_ot_config_file_access.yml) | SACL-audited reads of the Unit 3 turbine config and Helix Grid OptiCore paths | [`microsoft_winevtlog`](../../data/microsoft_winevtlog.xml.gz) (Security 4663) | medium | [T1005](https://attack.mitre.org/techniques/T1005/), [T1083](https://attack.mitre.org/techniques/T1083/) |
| [otread_scheduled_task](currentis_otread_scheduled_task.yml) | The `OTRead` scheduled task running a script from `C:\Users\Public` as the vendor account | [`microsoft_winevtlog`](../../data/microsoft_winevtlog.xml.gz) (process creation) | medium | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) |
| [wevtutil_security_log_clear](currentis_wevtutil_security_log_clear.yml) | `wevtutil cl Security` clearing the Security log on the OT host | [`microsoft_winevtlog`](../../data/microsoft_winevtlog.xml.gz) (process creation) | high | [T1070](https://attack.mitre.org/techniques/T1070/) |
| [security_eventlog_cleared](currentis_security_eventlog_cleared.yml) | The authoritative Security log-cleared event (1102) on the OT host | [`microsoft_winevtlog`](../../data/microsoft_winevtlog.xml.gz) (Security 1102) | high | [T1070](https://attack.mitre.org/techniques/T1070/) |

## Verification

Every rule was checked with `sigma check` (0 errors, 0 issues), counted against the
dataset, and converted to all three backends. The match count is the number of
dataset records that satisfy the rule's full condition, computed by decoding each log
to its native fields and applying the selection. Windows process-creation records
appear as both Sysmon Event ID 1 and Security 4688, so one action can be counted in
both, which is why some counts are small multiples.

| Rule | `sigma check` | Dataset matches | Splunk | Loki | Lucene |
|------|:---:|:---:|:---:|:---:|:---:|
| agentic_ai_shell_spawn | pass | 6 | yes | yes | yes |
| lotl_domain_recon | pass | 7 | yes | yes | yes |
| masqueraded_update_binary | pass | 4 | yes | yes | yes |
| c2_beacon_user_agent | pass | 33 | yes | yes | yes |
| c2_indicator_outbound | pass | 38 | yes | yes | yes |
| run_key_persistence | pass | 1 | yes | yes | yes |
| lsass_access_masqueraded_binary | pass | 1 | yes | yes | yes |
| vendor_credential_cmdkey_rdp | pass | 1 | yes | yes | yes |
| vendor_account_rdp_logon_ot | pass | 1 | yes | yes | yes |
| ot_config_file_access | pass | 28 | yes | yes | yes |
| otread_scheduled_task | pass | 2 | yes | yes | yes |
| wevtutil_security_log_clear | pass | 2 | yes | yes | yes |
| security_eventlog_cleared | pass | 1 | yes | yes | yes |

Converted queries are in [`conversions.md`](conversions.md). The Splunk and Lucene
conversions use [`pipelines/currentis_logsources.yml`](pipelines/currentis_logsources.yml),
which maps the Windows and Zeek logsources to `source=` filters; Loki needs no
pipeline. The standard pySigma windows and sysmon pipelines can be used instead.
Replace the sources with your own index or sourcetype.

Toolchain used for verification:

| Tool | Version |
|------|---------|
| sigma-cli | 3.1.0 |
| pySigma | 1.5.1 |
| pysigma-backend-splunk | 2.1.0 |
| pysigma-backend-elasticsearch (Lucene) | 2.1.1 |
| pysigma-backend-loki | 0.15.1 |

## Notes

- **Field names are the parsed representation.** The Windows rules use Sysmon and
  Security field names (`Image`, `ParentImage`, `CommandLine`, `TargetObject`,
  `SourceImage`, `TargetImage`, `ObjectName`, `TargetUserName`, `LogonType`,
  `EventID`). The Zeek rules use `user_agent` and `id.resp_h`. Map them to your own
  pipeline's field names before deploying.
- **ATT&CK tactic shortnames follow ATT&CK v18**, the version pySigma 1.5.1 bundles
  and `sigma check` validates against. v18 renamed the Defense Evasion tactic, so the
  masquerade rule is tagged `attack.stealth` and the log-clear rules
  `attack.defense-impairment`. The log-clear rules use the parent technique
  `attack.t1070` (Indicator Removal) because v18's set does not carry the
  `T1070.001` sub-technique. Technique IDs are otherwise unchanged.
- **ATT&CK for ICS is not in the Sigma tags.** The OT stages also map to ICS ATT&CK
  (T0859, T0822, T0888, T0882, T0831), which the Sigma enterprise tag namespace does
  not carry. See the dataset `dataset.yaml` and README for the ICS mapping.
- **Some rules depend on specific logging being on.** `run_key_persistence`,
  `lsass_access_masqueraded_binary`, and `masqueraded_update_binary` need Sysmon.
  `ot_config_file_access` needs an audit SACL on the OT paths (Security 4663).
  `lotl_domain_recon` and the other process rules need command-line auditing.
- **The threat-intel rule ages out.** `c2_indicator_outbound` matches a specific IP
  that was a documented C2 indicator at build time. Confirm it is still listed before
  alerting in production, and treat a match as a pivot, not a verdict.
- **These are samples.** Tune thresholds and false positives for your environment.
  The highest-fidelity signals here are the LSASS read from the masqueraded binary,
  the `cmdkey` TERMSRV staging of the vendor account, and the Security log clear. The
  C2-indicator rule is the lowest-confidence corroborating signal.
