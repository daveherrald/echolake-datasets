# T1552.004-14: Private Keys — Export Certificates with Mimikatz

## Technique Context

T1552.004 (Unsecured Credentials: Private Keys) includes adversary use of credential dumping tools to extract certificate private keys from the Windows certificate store. Mimikatz's `crypto::certificates` module enumerates certificates in specified stores and can export them as `.pfx` or `.der` files — including certificates whose private keys are marked as non-exportable. This is possible because Mimikatz accesses the key material directly from CryptoAPI/CNG key container files on disk (in `%ProgramData%\Microsoft\Crypto\RSA\` and similar locations) rather than going through the standard Windows cryptographic API export path, which enforces the non-exportable flag.

The command executed is:
```
"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\x64\mimikatz.exe"
  "crypto::certificates /systemstore:local_machine /store:my /export" exit
```

This targets the local machine's Personal certificate store (`local_machine\my`) and exports all certificates found there. In enterprise environments, workstations may hold code-signing certificates, machine authentication certificates (for 802.1x or VPN), or web server certificates, all of which may have valuable key material.

In the defended variant, Windows Defender blocked the Mimikatz binary before it could execute, killing the process at launch. The Security EID 4688 and Sysmon EID 1 records appeared for `cmd.exe` launching Mimikatz, but Mimikatz itself produced no activity before termination.

In this undefended run, Defender was disabled and the Mimikatz binary was free to execute `crypto::certificates` against the certificate store.

## What This Dataset Contains

The dataset spans approximately four seconds of telemetry (2026-03-17T17:20:31Z–17:20:35Z) across three log sources, with 115 total events.

**Security EID 4688 — three process creates:**
1. `whoami.exe` (PID 0x44e4) — ART pre-check
2. `cmd.exe` (PID 0x453c) launching Mimikatz:
   ```
   "cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\x64\mimikatz.exe" "crypto::certificates /systemstore:local_machine /store:my /export"  exit
   ```
3. `whoami.exe` (PID 0x44bc) — post-execution check

The `cmd.exe` command (PID 0x453c) is the pivotal event. It documents the full invocation with explicit store targets (`local_machine`, `my`), the `export` action, and the path to the Mimikatz binary. This record appears in the Security log before Mimikatz has a chance to run — it fires at the moment `cmd.exe` is created with these arguments.

**Sysmon EID breakdown — 16 events: 9 EID 7, 3 EID 10, 3 EID 1, 1 EID 17:**

The 16-event Sysmon count is the lowest of any test in this batch, and notably lower than the defended dataset (which had 17 Sysmon events). The composition is telling:

- **EID 1 (Process Create)**: Three events. `whoami.exe` (PID 17636, tagged `T1033`) is recorded. The `cmd.exe` launch (PID 17724, tagged `technique_id=T1059.003,technique_name=Windows Command Shell`) is recorded with the full Mimikatz command line. A second `whoami.exe` (PID 17596, tagged `T1033`) appears for the post-check.
- **EID 10 (Process Access)**: Three events. The test framework `powershell.exe` (PID 15800) opens `whoami.exe` (PID 17636) with `GrantedAccess: 0x1FFFFF`. Then it opens `cmd.exe` (PID 17724) with `GrantedAccess: 0x1FFFFF` — this is the standard ART test framework child process management access pattern.
- **EID 7 (Image Load)**: Nine events — the PowerShell startup DLL load sequence for the test framework `powershell.exe`. Critically, **no EID 7 events appear for `mimikatz.exe`**. In an undefended run where Mimikatz executes successfully, you would expect EID 7 events for `mimikatz.exe` loading `cryptbase.dll`, `ncrypt.dll`, `crypt32.dll`, and other cryptographic DLLs. Their absence requires explanation.
- **EID 17 (Pipe Create)**: One event — the test framework `powershell.exe` creating its console host pipe.

The absence of Mimikatz DLL load events is the defining forensic characteristic. Two possible explanations: (1) Mimikatz ran very quickly within the four-second window and its DLL loads did not reach Sysmon before the process terminated, or (2) a residual Defender component (AMSI or a scan triggered by the binary) terminated the process quickly enough to prevent DLL load events from being generated. The Security EID 4688 confirms `cmd.exe` was created and the Mimikatz invocation was recorded, and the absence of a second `cmd.exe` EID 4688 with an exit code or blocked status suggests the process lifecycle was normal from the OS perspective.

**PowerShell — 96 events: 95 EID 4104, 1 EID 4103:**
No EID 4100 errors — Mimikatz is invoked as a native binary via `cmd.exe`, not as a PowerShell script, so AMSI does not evaluate it. The single EID 4103 event records `Set-ExecutionPolicy Bypass -Scope Process -Force` — the standard ART test framework setup. The 95 EID 4104 script blocks are dominated by test framework boilerplate; no Mimikatz-specific script content appears since Mimikatz runs natively.

## What This Dataset Does Not Contain

No Mimikatz process image load events (Sysmon EID 7 for `mimikatz.exe`) appear. This absence is the most significant gap between what we expect from a fully successful undefended execution and what the data shows. In a clear-path Mimikatz execution, you would observe EID 7 events for cryptographic libraries loaded into the Mimikatz process space.

No exported certificate files appear (Sysmon EID 11). If Mimikatz successfully executed `crypto::certificates /export`, it would write `.pfx` or `.der` files to the current working directory (`C:\Windows\TEMP\`). No such EID 11 events appear — consistent with the EID 7 absence suggesting either very rapid execution or early termination.

No Security EID 4985 (Certificate Services Issued a Certificate) or EID 70 (Certificate Export) events appear — the audit policy does not capture CryptoAPI certificate store access at this granularity.

## Assessment

This dataset occupies an ambiguous position relative to the defended variant. The defended dataset showed Defender explicitly killing Mimikatz (no DLL loads, immediate exit). This undefended dataset also shows no Mimikatz DLL loads, which means either Mimikatz ran and exited faster than Sysmon could record its DLL loads, or some residual protection mechanism acted. The Security EID 4688 and Sysmon EID 1 records for the `cmd.exe` Mimikatz invocation are identical between defended and undefended variants — they document the invocation intent in both cases. The undefended run's primary contribution is the confirmation that no explicit block event (Process Terminated, AMSI error, Security 4688 exit code) appears, leaving a forensically ambiguous signal. For detection engineers, the Security EID 4688 command line containing `crypto::certificates` and the Mimikatz path provides detection that fires identically in both variants — making this a case where the defended dataset is equally valuable for detection validation.

## Detection Opportunities Present in This Data

1. Security EID 4688 with `ProcessCommandLine` containing `mimikatz.exe` — present in both defended and undefended runs, fires before Defender can block and before Mimikatz executes.

2. Security EID 4688 with `ProcessCommandLine` containing `crypto::certificates` — the specific Mimikatz module and action pair. This is a high-confidence indicator specific to certificate export operations.

3. Sysmon EID 1 tagged `T1059.003` (Windows Command Shell) for `cmd.exe` with `CommandLine` containing both `mimikatz.exe` and `crypto::certificates` — the Sysmon rule correctly classifies this as a Windows Command Shell invocation and captures the full command line.

4. Sysmon EID 10 (Process Access) from `powershell.exe` opening `cmd.exe` with `GrantedAccess: 0x1FFFFF` where the `cmd.exe` commandline targets a known attack tool — the process access event combines with the process create event for a richer behavioral signal.

5. File system monitoring for `mimikatz.exe` execution anywhere outside of `C:\AtomicRedTeam\` or similar known-test paths — or for any process named `mimikatz.exe` at all, which has no legitimate production use.

6. Absence-based detection: Security EID 4688 for `cmd.exe /c <path>\mimikatz.exe` without a corresponding Sysmon EID 7 showing Mimikatz's cryptographic DLL loads within 2-3 seconds may indicate the binary was killed before initialization — this pattern distinguishes Defender-blocked execution (where the block is explicit) from forensically ambiguous rapid execution.
