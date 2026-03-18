# T1564-1: Hide Artifacts — Extract Binary Files via VBA

## Technique Context

MITRE ATT&CK T1564 (Hide Artifacts) covers techniques adversaries use to prevent their
tools, files, and activity from being noticed. This test embeds a binary payload inside
an Office VBA macro and extracts it to disk at execution time. The payload — `extractme.bin`
— is encoded within the macro source rather than stored as a standalone file, making it
invisible to file-system scans before the document is opened. The technique is a staple
of initial access and staging: the document appears to contain only legitimate content, and
the payload only materializes after the VBA macro runs.

The test uses `Invoke-MalDoc`, a helper from the Atomic Red Team library that drives Word
programmatically via COM automation from PowerShell, enabling automated macro execution
without a live user session.

In the defended variant, Windows Defender's real-time protection was active. The test
completed process execution (the `Write-Host "DONE"` confirmed completion), but no evidence
of the extracted binary appeared in collected events, and a Sysmon EID 3 network connection
from `MsMpEng.exe` (Defender) appeared — consistent with Defender cloud-scanning the
download. The `Invoke-MalDoc` source was fetched live from `raw.githubusercontent.com`.

## What This Dataset Contains

With Defender disabled, the full test lifecycle executes. The dataset spans approximately
5 seconds (17:40:57–17:41:02 UTC) and contains 181 total events across four channels.

**PowerShell channel (166 events) — EIDs 4104, 4103, 4100:**

The dominant content is ART test framework boilerplate (161 EID 4104 events with internal error-
handling fragments). The substantive attack-relevant content appears in:

- EID 4104 `Set-ExecutionPolicy Bypass -Scope Process -Force` — test framework setup
- EID 4103 `Write-Host "DONE"` — confirming full test completion

The `Invoke-MalDoc` function body and the macro-injection command would be captured in
EID 4104 blocks during execution in the defended dataset. In this undefended dataset the
same boilerplate pattern appears, confirming the test framework ran, but the full `Invoke-MalDoc`
source (fetched from GitHub at runtime) is not represented in the 20 sampled events. The
download and execution occurred within the test framework's child `powershell.exe` process.

**Security channel (13 events) — EIDs 4688, 4689, 4703:**

EID 4688 records show:
- `whoami.exe` spawned by `powershell.exe` (ART pre-flight), exiting `0x0`
- A child `powershell.exe` with command line `"powershell.exe" & {$ma...` — the `$ma`
  prefix is consistent with the macro-injection block (`$macro = [System.IO.File]::ReadAllText(...)`)
  visible in the defended 4104 log
- That child `powershell.exe` exiting `0x0` (success), confirming the macro extraction
  ran to completion without Defender interference

EID 4703 records a token right adjustment on the SYSTEM account, enabling elevated
privilege operations during macro execution. The enabled privileges include
`SeAssignPrimaryTokenPrivilege`, `SeLoadDriverPrivilege`, and `SeBackupPrivilege`.

**Sysmon channel (1 event) — EID 22:**

Sysmon EID 22 (DNS query) records:
```
QueryName: raw.githubusercontent.com
QueryStatus: 0
QueryResults: ::ffff:185.199.109.133;::ffff:185.199.110.133;::ffff:185.199.111.133;::ffff:185.199.108.133
Image: <unknown process>
User: NT AUTHORITY\SYSTEM
UtcTime: 2026-03-17 17:40:59.822
```

The `<unknown process>` image name indicates the process exited before Sysmon could resolve
its PID to a path. This DNS query confirms the live download of `Invoke-MalDoc` from
GitHub during test execution.

**Application channel (1 event) — EID 15:**

`Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON.` — the test framework
re-enables Defender after the test completes, confirming Defender was disabled during execution.

## What This Dataset Does Not Contain

**No network connection event (Sysmon EID 3) for the GitHub download.** The DNS lookup is
captured (EID 22), confirming name resolution succeeded, but the TCP connection to
`185.199.109.133:443` that followed is not present as a Sysmon EID 3. This matches the
pattern seen in other tests: .NET HTTP client connections do not always surface as Sysmon
network events depending on the protocol stack path.

**No file creation event (Sysmon EID 11) for `extractme.bin`.** The binary payload extracted
from the VBA macro to disk is not recorded as a file creation event. The sysmon-modular
file creation rules target specific extensions and locations; the `.bin` extension at
`C:\AtomicRedTeam\atomics\T1564\bin\extractme.bin` was not matched by the configured rules.

**No Office process events.** `WINWORD.EXE` does not appear in Security 4688 or Sysmon EID
1 records. `Invoke-MalDoc` drives Word via COM automation from PowerShell, and WINWORD.EXE
does not match the sysmon-modular include-mode ProcessCreate criteria. The binary extraction
happens inside the Word COM session and is not reflected in process creation telemetry.

**No Defender detection events.** With Defender disabled, there are no EID 1116 or 1117
(malware detection) events. In a defended environment, the extracted `extractme.bin` would
likely trigger a detection after extraction.

## Assessment

This dataset captures the network delivery stage of the attack — the GitHub download of
`Invoke-MalDoc` is visible through the EID 22 DNS query — but the core artifact (the
extracted binary written to disk) is invisible in the collected telemetry. The child
`powershell.exe` with command line starting `"powershell.exe" & {$ma...` exiting `0x0`
confirms the macro extraction ran and completed without error.

Compared to the defended variant, the key difference is outcome: the child process exits
cleanly here rather than being blocked, and no Defender cloud-lookup network connection
appears. The telemetry gap for the actual binary file write is present in both variants
— the extraction artifact is below the threshold of configured Sysmon file monitoring
either way.

## Detection Opportunities Present in This Data

**Sysmon EID 22 — DNS query to `raw.githubusercontent.com`:** PowerShell or any process
under SYSTEM fetching content from GitHub raw URLs during macro execution is a detectable
pattern. The `<unknown process>` image is itself suspicious — a process that exited before
Sysmon resolved its PID indicates very short-lived execution, characteristic of in-memory
download chains.

**Security EID 4688 — child `powershell.exe` with `$ma` prefix:** The command line fragment
`"powershell.exe" & {$ma...` is consistent with macro content injection. Combined with the
parent being `powershell.exe` running as SYSTEM and the SYSTEM privilege set enabled via
EID 4703, this chain is anomalous for legitimate activity.

**Security EID 4703 — SYSTEM privilege elevation:** The token right adjustment enabling
`SeAssignPrimaryTokenPrivilege`, `SeLoadDriverPrivilege`, `SeBackupPrivilege`, and
`SeRestorePrivilege` during a PowerShell session is uncommon in normal workstation operation
and warrants investigation.

**Absence of Defender events combined with successful execution:** In environments where
Defender should be running, the complete absence of Defender-related application events
(EID 15 showing `SECURITY_PRODUCT_STATE_ON` being *set* rather than already on) is itself
an indicator that defenses were tampered with before the payload ran.
