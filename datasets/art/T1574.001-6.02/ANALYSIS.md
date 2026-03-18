# T1574.001-6: DLL Search Order Hijacking — DLL Search Order Hijacking, DLL Sideloading Of KeyScramblerIE.DLL Via KeyScrambler.EXE

## Technique Context

T1574.001 (Hijack Execution Flow: DLL Search Order Hijacking) includes DLL side-loading through legitimate third-party software installers. `KeyScrambler` is a commercial keystroke encryption tool from QFX Software. Its main executable (`KeyScrambler.exe`) loads `KeyScramblerIE.dll` from its installation directory by relative path. An attacker who can write a malicious `KeyScramblerIE.dll` to that installation directory — or who copies `KeyScrambler.exe` to a directory alongside a planted DLL — can cause the legitimate signed binary to load attacker-controlled code.

This test downloads and silently installs KeyScrambler from the official vendor website (`download.qfxsoftware.com`), then exploits the side-loading opportunity with the installed binary. It is one of the more realistic tests in this batch: it involves a live internet download, a full software installer, kernel driver installation, and COM registration — all the complexity of a real supply chain or lure-based attack.

## What This Dataset Contains

The dataset captures 185 events across six log sources: PowerShell (112 events: 100 EID 4104, 12 EID 4103), Security (65 events: 34 EID 4689, 27 EID 4688, 1 EID 4627, 1 EID 4624, 1 EID 4672, 1 EID 4703), Sysmon (2 events: EID 22, EID 3), System (4 events: 2 EID 7045, 1 EID 7040, 1 EID 26), Application (1 event: EID 4097), and WMI (1 event: EID 5858). This is the richest dataset in this batch, reflecting the full software installation lifecycle.

**The installer download and execution are confirmed by Sysmon events.** Sysmon EID 22 (DNS query) shows:

```
QueryName: download.qfxsoftware.com
QueryResults: ::ffff:173.255.203.95
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

Sysmon EID 3 (Network connection) records the HTTPS connection:

```
Image: powershell.exe
DestinationIp: 173.255.203.95
DestinationPort: 443
Protocol: tcp
Initiated: true
```

Security EID 4688 confirms the installer ran silently:

```
New Process Name: C:\Windows\Temp\KeyScrambler_Setup.exe
Process Command Line: "C:\Windows\TEMP\KeyScrambler_Setup.exe" /S
Creator Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

The installer spawned the full installation chain, captured across multiple EID 4688 events:

- `regsvr32.exe /s /u "C:\Program Files (x86)\KeyScrambler\x64\KeyScramblerIE.dll"` — initial DLL un-registration
- `regsvr32.exe /s "C:\Program Files (x86)\KeyScrambler\x64\KeyScramblerIE.dll"` — DLL registration
- `icacls keyscrambler\KeyScramblerIE.dll /grant everyone:RX *S-1-15-2-1:RX *S-1-15-2-2:RX` — permission grant

System EID 7045 records two new services being installed:

```
Service Name: KeyScrambler
Service File Name: System32\drivers\keyscrambler.sys
Service Type: kernel mode driver
Service Start Type: demand start
```

```
Service Name: QFX Software Update Service
Service File Name: C:\Program Files (x86)\KeyScrambler\x64\QFXUpdateService.exe
Service Type: user mode service
```

System EID 26 captures the payload DLL missing error popup:

```
KeyScrambler.exe - System Error: The code execution cannot proceed because KeyScramblerIE.DLL was not found. Reinstalling the program may fix this problem.
```

This error confirms the side-loading attempt: `KeyScrambler.exe` was invoked from a location where `KeyScramblerIE.dll` was not present (or was missing the malicious copy), triggering the DLL-not-found dialog.

The cleanup phase recorded in Security EID 4688 includes:

```
"C:\Program Files (x86)\KeyScrambler\Uninstall.exe" /S
"C:\Windows\TEMP\~nsu1.tmp\Un.exe" /S _?=C:\Program Files (x86)\KeyScrambler\
```

PowerShell EID 4104 confirms the cleanup script block:

```
Remove-Item -Path $env:Temp\KeyScrambler_Setup.exe
Start-Process -FilePath "C:\Program Files (x86)\KeyScrambler\Uninstall.exe" -ArgumentList /S -Wait
Remove-Item -Path $env:Temp\KeyScrambler.exe
```

Security EID 4624 (Logon Type 5), 4627 (Group Membership), and 4672 (Special Privileges) reflect a SYSTEM service logon triggered by the installer's service registration activity — consistent with the kernel driver being installed.

Application EID 4097 records an automatic root certificate update for `GlobalSign Root CA - R6`, triggered by the installer's certificate validation.

WMI EID 5858 shows a failed WMI query (`HRESULT: 0x80041032`) from the ART test framework monitoring for `wsmprovhost.exe` — a benign test framework artifact.

System EID 7040 records the Background Intelligent Transfer Service (BITS) start type being changed from automatic to demand — an incidental side effect of the test environment.

## What This Dataset Does Not Contain

**No Sysmon EID 7 (Image Loaded) for the KeyScramblerIE.dll side-load itself.** While the EID 26 popup confirms the DLL was not found in the expected location, you cannot confirm from this data whether an attacker-controlled `KeyScramblerIE.dll` was successfully loaded by `KeyScrambler.exe` during any part of the test. The error message indicates the attempted execution hit the missing-DLL path.

**No file write events for the malicious DLL.** The dataset does not include Sysmon EID 11 records showing an attacker-controlled DLL being written to the installation directory.

**The Security log does not include a `KeyScrambler.exe` process creation event** showing it being launched with a planted DLL. The EID 26 popup is the only record of the attempted execution.

## Assessment

The defended variant recorded 4 Sysmon, 59 Security, 55 PowerShell, and 2 System events. The undefended run produced a substantially richer dataset: 2 Sysmon, 65 Security, 112 PowerShell, 4 System events, plus Application and WMI events. The undefended run completes the full installation and uninstallation cycle, including kernel driver installation and COM DLL registration, which are absent or blocked in the defended variant.

The most significant addition is System EID 7045 — two new services being installed — and the DNS/network events confirming the live download from `download.qfxsoftware.com`. These are direct evidence of a real-world installer running end-to-end. The EID 26 popup (KeyScramblerIE.DLL not found) indicates the side-load was attempted but the DLL was absent in the location where `KeyScrambler.exe` searched — either the attack's DLL placement step did not complete, or the EXE was run from a directory without the planted DLL.

## Detection Opportunities Present in This Data

**Sysmon EID 22 / EID 3 — PowerShell downloading from a software vendor domain followed immediately by silent installer execution.** The sequence of `powershell.exe` → DNS query for `download.qfxsoftware.com` → HTTPS download → `KeyScrambler_Setup.exe /S` is a textbook lure-based installer pattern. Legitimate software deployments use SCCM, Intune, or other managed distribution channels, not PowerShell downloading from vendor websites.

**System EID 7045 — Kernel-mode driver installation from a script-driven context.** A kernel driver (`keyscrambler.sys`) being installed by a process chain rooted in a PowerShell ART test framework is a significant event. Driver installations initiated from non-administrative deployment tooling are uncommon.

**Security EID 4688 — regsvr32.exe invoked by `KeyScrambler_Setup.exe`.** The installer registering and unregistering its own COM DLL is expected behavior for KeyScrambler — but `regsvr32.exe` being spawned from a temp-directory installer in a scripted context is a pattern worth baselining.

**System EID 26 — Application popup for missing DLL.** A `DLL not found` error for `KeyScramblerIE.DLL` from a process run outside its expected installation directory is a direct indicator of a side-loading attempt. Legitimate usage of `KeyScrambler.exe` occurs from `C:\Program Files (x86)\KeyScrambler\`, not from a temp path.

**Security EID 4624/4627/4672 — Service logon with full privilege set.** The installer triggering a SYSTEM service logon (Logon Type 5) for the kernel driver installation, combined with the special privilege assignment in EID 4672 (including `SeLoadDriverPrivilege`), is observable and correlatable with the concurrent driver installation events.
