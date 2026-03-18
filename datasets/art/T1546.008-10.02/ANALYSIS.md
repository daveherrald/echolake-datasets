# T1546.008-10: Accessibility Features — Replace AtBroker.exe with cmd.exe

## Technique Context

T1546.008 (Accessibility Features) covers the well-known technique of replacing Windows accessibility binaries — executables that the OS launches in high-privilege contexts at the logon screen or via keyboard shortcuts — with a shell or backdoor. The classic targets are `sethc.exe` (Sticky Keys), `utilman.exe` (Ease of Access), and `osk.exe` (On-Screen Keyboard). This test targets `AtBroker.exe` (Assistive Technology Broker), a less commonly discussed accessibility binary that Windows launches to mediate assistive technology applications.

By substituting `cmd.exe` for `AtBroker.exe`, an attacker achieves a backdoor that opens a SYSTEM-privileged command prompt at the logon screen, accessible without authentication. This variant is notable because signature-based detections that check only the canonical three targets (`sethc.exe`, `utilman.exe`, `osk.exe`) will miss it. The replacement methodology is identical across all targets: take ownership with `takeown.exe`, grant write permissions with `icacls.exe`, then `copy /Y` the shell binary over the accessibility executable.

In the defended variant (30 Sysmon, 15 Security, 34 PowerShell from an earlier run on ACME-WS02), the file copy *succeeded* — Defender did not block it, and Sysmon EID 11 confirmed the write to `AtBroker.exe`. This undefended dataset from ACME-WS06 shows the same pattern.

## What This Dataset Contains

The dataset spans 3 seconds (2026-03-17 17:06:54–17:06:57 UTC) on ACME-WS06 running as NT AUTHORITY\SYSTEM. It contains 131 events across three channels: 107 PowerShell, 20 Sysmon, and 4 Security.

**Security (4 events, EID 4688):** Four process creation events document the full setup and cleanup:

Setup phase:
1. `"C:\Windows\system32\whoami.exe"` — test framework pre-flight (creator: `powershell.exe`)
2. The complete file replacement command:
```
"cmd.exe" /c IF NOT EXIST C:\Windows\System32\AtBroker_backup.exe (copy C:\Windows\System32\AtBroker.exe C:\Windows\System32\AtBroker_backup.exe) ELSE ( pushd ) & takeown /F C:\Windows\System32\AtBroker.exe /A & icacls C:\Windows\System32\AtBroker.exe /grant Administrators:F /t & copy /Y C:\Windows\System32\cmd.exe C:\Windows\System32\AtBroker.exe
```

Cleanup phase:
3. `"C:\Windows\system32\whoami.exe"` — post-execution test framework check
4. `"cmd.exe" /c copy /Y C:\Windows\System32\AtBroker_backup.exe C:\Windows\System32\AtBroker.exe` — ART cleanup: restoring the original binary

The setup command is a compound sequence: first, back up the original `AtBroker.exe` if not already done; then `takeown`, `icacls`, and `copy /Y cmd.exe` over it. The cleanup simply restores from the backup. Both phases are fully captured.

**Sysmon (20 events, EIDs 1, 7, 10, 11, 17):** Sysmon EID 1 captures two process creations in the samples: `whoami.exe` (tagged `T1033`) and the `cmd.exe` setup command (tagged `RuleName: technique_id=T1083,technique_name=File and Directory Discovery`). The T1083 tag is a sysmon-modular classification artifact — the ruleset matched this `cmd.exe` invocation as a file/directory discovery pattern. The full command line including all four chained operations (`IF NOT EXIST…copy…takeown…icacls…copy /Y`) is preserved.

Critically, Sysmon EID 11 (FileCreate) records `C:\Windows\System32\AtBroker_backup.exe` being created at `2026-03-17 17:06:56.336 UTC` by `cmd.exe` (PID 18168). This confirms the backup step ran — and by implication, that the original `AtBroker.exe` was available to be backed up (i.e., the file had not already been replaced). The EID 11 record does not show a write to `AtBroker.exe` itself (the replacement), but the backup creation confirms the commands were executing against a clean system.

EID 7 records 9 DLL load events (PowerShell runtime and `.NET` dependencies). EID 10 fires four times (ProcessAccess, GrantedAccess `0x1FFFFF`, tagged `T1055.001`). EID 17 records one named pipe create.

**PowerShell (107 events, EIDs 4103, 4104):** All test framework boilerplate. The technique was invoked via `cmd.exe`, so no technique-relevant PowerShell script blocks appear. EID 4103 records 3 module logging events; EID 4104 records 104 formatter stubs.

## What This Dataset Does Not Contain

- **No Sysmon EID 11 for `AtBroker.exe` overwrite.** The backup file (`AtBroker_backup.exe`) creation is captured, but the subsequent `copy /Y cmd.exe AtBroker.exe` overwrite is not recorded as an EID 11 in the surfaced samples. This may be because the sysmon-modular configuration does not specifically target `AtBroker.exe` writes (it targets more specific patterns), or the EID 11 for the overwrite falls outside the 20 sampled events.
- **No `takeown.exe` or `icacls.exe` EID 1.** These sub-operations within the compound `cmd.exe` command line are not captured as separate Sysmon EID 1 entries in the 20 surfaced samples — they appear to have run as internal shell operations within the `cmd.exe` context. The defended variant on ACME-WS02 captured `takeown.exe` and `icacls.exe` as separate EID 1 events tagged `T1222.001`; those are not present in this undefended ACME-WS06 dataset. Security EID 4688 does not capture them either — only the `cmd.exe` creation is logged, not the sub-processes it spawns internally via `&` operators.
- **No Defender block.** Both the defended and undefended variants show the replacement succeeding. Defender does not appear to block `AtBroker.exe` modification on this system configuration.
- **No trigger confirmation.** The dataset does not include any event showing `AtBroker.exe` being *invoked* at the logon screen — the persistence is planted but not triggered during the test window.

## Assessment

This dataset is one of the cleaner persistence examples in the batch. The setup command is fully captured in Security EID 4688 and Sysmon EID 1, the backup file creation is confirmed in Sysmon EID 11, and the cleanup restoration is documented. The three-step pattern — take ownership, grant permissions, overwrite — is visible as a single compound command line, which is exactly how this technique appears in the wild when scripted.

The comparison with the defended variant is instructive: the defended run on ACME-WS02 captured `takeown.exe` and `icacls.exe` as separate Sysmon EID 1 events (tagged `T1222.001`), while this undefended run on ACME-WS06 does not. This difference likely reflects Sysmon configuration differences between the two machines' collection windows, not Defender interference — the technique executed without blocks in both cases. This illustrates how telemetry coverage varies across nominally identical collection configurations, particularly for sub-processes spawned within compound `cmd.exe` `&`-chained commands.

The T1083 RuleName tag on the setup `cmd.exe` is a classification artifact that would cause false-negative filtering in any detection that relies on the Sysmon RuleName field to identify T1546.008 activity. The command line content — not the rule tag — is the reliable indicator.

## Detection Opportunities Present in This Data

- **Security EID 4688 command line:** The full compound command including `takeown`, `icacls`, and `copy /Y cmd.exe AtBroker.exe` is captured verbatim in a single `cmd.exe` process creation event. The combination of `takeown`, `icacls /grant`, and `copy /Y` targeting a System32 accessibility binary (`AtBroker.exe`) is a high-specificity indicator pattern.
- **Sysmon EID 11 for `AtBroker_backup.exe` creation:** The creation of `*_backup.exe` files in `C:\Windows\System32\` by `cmd.exe` is a signature of this ART test's approach to atomic backup-then-replace. Any write to System32 that creates a `*_backup.exe` alongside an accessibility binary overwrite is highly suspicious.
- **`C:\Windows\System32\AtBroker.exe` write (indirect):** Even without a direct Sysmon EID 11 for the overwrite, the compound command line proves intent and the backup confirms execution. In a production environment, File Integrity Monitoring or Sysmon EID 11 with broader System32 coverage would capture the actual `AtBroker.exe` write.
- **`cmd.exe` spawned by SYSTEM PowerShell targeting System32 accessibility binaries:** The parent chain `powershell.exe → cmd.exe` with a command line containing System32 accessibility binary paths (`AtBroker.exe`, `sethc.exe`, `utilman.exe`, etc.) combined with `takeown` or `icacls` is a reliable behavioral indicator for the T1546.008 family regardless of which specific binary is targeted.
- **Cleanup signature:** The `copy /Y AtBroker_backup.exe AtBroker.exe` cleanup command is ART-specific and, if present, identifies test-generated activity. In a real intrusion, this would be absent — the attacker would leave the replacement in place.
