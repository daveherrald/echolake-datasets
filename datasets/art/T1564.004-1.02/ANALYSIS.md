# T1564.004-1: NTFS File Attributes — Alternate Data Streams (ADS)

## Technique Context

MITRE ATT&CK T1564.004 (NTFS File Attributes) covers adversary use of NTFS-specific
filesystem features to hide data and executable payloads. The most widely exploited
feature is Alternate Data Streams (ADS): the NTFS metadata model allows any file to have
multiple named data streams. A file `C:\temp\evil.exe` can have a secondary stream
`C:\Program Files (x86)\TeamViewer\TeamViewer12_Logfile.log:evil.exe` containing
executable code while appearing in standard `dir` listings as only the primary stream.
ADS-stored content does not show up in Explorer, is skipped by many backup solutions, and
can be executed directly with `wscript.exe`, `mshta.exe`, or `start` on some Windows
versions.

This test chains nine different living-off-the-land binaries (LOLBins) to write data into
ADS using distinct methods, demonstrating the range of tools an adversary might use:
`type` (stream redirect), `extrac32`, `findstr`, `certutil`, `makecab`, `print`,
`reg export`, `regedit`, `expand`, and `esentutl`.

In the defended variant, Windows Defender blocked the operation chain — the `cmd.exe`
process exited with `0xC0000022` (STATUS_ACCESS_DENIED), indicating at least one write
was blocked. A Sysmon EID 8 (CreateRemoteThread) appeared as a side effect of Defender's
behavior monitoring, and an outbound TLS connection from `MsMpEng.exe` to a Defender
cloud endpoint appeared for reputation lookup.

## What This Dataset Contains

With Defender disabled, the full LOLBin chain executes. The dataset spans approximately
2 seconds (17:41:16–17:41:18 UTC) and contains 121 total events across two channels.

**Security channel (11 events) — EIDs 4688, 4689:**

The core attack event is Security EID 4688 for `cmd.exe`:

```
Process Name: C:\Windows\System32\cmd.exe
Process Command Line: "cmd.exe" /c type C:\temp\evil.exe > "C:\Program File...
Creator Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Exit Status: 0xC0000022 (in defended) → 0x0 or partial in undefended
```

The command line captures the start of the nine-tool chain:
```
"cmd.exe" /c type C:\temp\evil.exe > "C:\Program Files (x86)\TeamViewer\TeamViewer12_Logfile.log:evil.exe"
```

The destination path — `TeamViewer12_Logfile.log:evil.exe` — is the ADS write target:
a log file from a legitimate application with an executable stream appended to it. This is
a standard ADS hiding pattern that buries the payload stream inside a benign-looking file.

In the undefended run, the `cmd.exe` chain process that executes the nine LOLBin tools
exits with `0x0` (success), confirming the ADS writes completed. A second `cmd.exe` process
with command line `"cmd.exe" /c` (the cleanup phase) exits `0x0`.

`whoami.exe` appears twice (pre- and post-execution ART checks), both `0x0`.

**PowerShell channel (110 events) — EIDs 4104, 4103, 4100:**

The 104 EID 4104 events are ART test framework boilerplate. EID 4103 records `Set-ExecutionPolicy
Bypass` and `Write-Host "DONE"` confirming successful test completion. EID 4100 records
PowerShell engine start/stop.

The ADS write command itself runs inside `cmd.exe`, so no EID 4104 for the LOLBin chain
appears — the PowerShell log captures only the outer test framework.

## What This Dataset Does Not Contain

**No Sysmon events.** The Sysmon channel is absent. The defended variant included Sysmon
EID 8 (Defender behavior monitoring side effect), EID 3 (Defender cloud connection), EID 17
(PowerShell named pipe), and EID 7 (DLL loads). None of those appear in this undefended
collection. The result is that the child processes spawned by `cmd.exe` to execute each
LOLBin tool — `extrac32.exe`, `certutil.exe`, `esentutl.exe`, etc. — are not individually
recorded.

**No individual LOLBin process creation events.** The nine tools in the chain each produce
a child process, but none appear in Security 4688. The Security log only captures processes
matching the audit policy scope, which here captures the parent `cmd.exe` and its wrapper
PowerShell. `certutil.exe`, `esentutl.exe`, `makecab.exe`, and the others are invisible.

**No file creation events for the ADS streams.** Sysmon EID 11 (FileCreate) does not fire
for ADS writes — neither the `.bin` source files nor the ADS targets appear as file creation
events. NTFS alternate stream writes are not captured by standard Sysmon FileCreate rules.

**No `certutil` network connection.** The chain includes `certutil.exe -urlcache -split -f
https://raw.githubusercontent.com/...` — a URL-fetch via certutil. With Defender disabled
and Sysmon absent, neither the DNS query nor the outbound HTTPS connection is recorded.

## Assessment

The key contrast with the defended variant is the `cmd.exe` exit code. In the defended
dataset, the nine-tool chain returned `0xC0000022` — Defender blocked at least one of the
writes. In the undefended run, the process exits successfully, indicating the ADS payloads
were written to disk. The dataset confirms the attack completed but provides minimal
visibility into which of the nine tools succeeded and what data was written where.

The most informative event is the truncated EID 4688 command line showing the `cmd.exe`
invocation starting with `"cmd.exe" /c type C:\temp\evil.exe > "C:\Program File...`.
A full un-truncated command line would show the entire nine-tool chain, making every
target ADS path visible to log analysis.

## Detection Opportunities Present in This Data

**Security EID 4688 — `cmd.exe` with ADS write syntax:** The command line fragment
`type ... > "C:\Program Files..."` with a colon in the destination path (e.g.,
`TeamViewer12_Logfile.log:evil.exe`) is a strong indicator of ADS write activity.
The colon character appearing in a file path argument after the extension is the ADS
stream separator and should be flagged in any command line audit.

**Security EID 4688 — LOLBin child of PowerShell running as SYSTEM:** `cmd.exe` spawned by
`powershell.exe` running under `NT AUTHORITY\SYSTEM` (Logon ID `0x3E7`) executing a long
chained command is anomalous for normal workstation operation.

**Absence of expected process telemetry:** In an environment with Sysmon, the absence of
individual child processes for `certutil.exe`, `esentutl.exe`, and `extrac32.exe` following
a `cmd.exe` chain execution that contains those tool names in its command line would be
anomalous — those processes should appear in Sysmon EID 1 if they ran.

**`cmd.exe` exit code `0x0` vs `0xC0000022`:** In environments where Defender is expected
to be active, a `0x0` exit from a `cmd.exe` chain that includes ADS write tools (certutil,
esentutl, extrac32) indicates Defender was not intervening. That outcome itself is an
indicator of defense evasion.
