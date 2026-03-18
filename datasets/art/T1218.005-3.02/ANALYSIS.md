# T1218.005-3: Mshta — Mshta Executes Remote HTML Application (HTA)

## Technique Context

T1218.005 (Mshta) covers abusing `mshta.exe`, the Microsoft HTML Application Host, to execute arbitrary code. This test demonstrates downloading an HTA file from a remote URL and executing it, with the HTA written to the user's Startup folder for persistence. The technique uses PowerShell to fetch the HTA from GitHub via `Invoke-WebRequest`, writes it to `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\T1218.005.hta`, then invokes `mshta.exe` against the local copy.

This is a two-phase technique: a download-and-persist phase (PowerShell fetching the HTA and writing to Startup) and an execution phase (mshta.exe running the local HTA file). The Startup folder placement ensures the HTA executes at next user logon, adding a persistence dimension beyond the immediate execution.

## What This Dataset Contains

The dataset contains a single timestamp (2026-03-14T23:59:59Z) across 121 total events: 110 PowerShell, 11 Sysmon. The timestamp indicates this test ran on an earlier date than the other tests in this batch — 2026-03-14 rather than 2026-03-17.

**Sysmon image load events (EID 7, 9 events):** The dataset captures `powershell.exe` (PID 2068) loading the standard .NET runtime DLL set: `mscoree.dll`, `mscoreei.dll`, `clr.dll`, `mscorlib.ni.dll`, `System.Management.Automation.ni.dll`, `clrjit.dll`, `MpOAV.dll`, `MpClient.dll`, and `urlmon.dll`. The `urlmon.dll` (OLE32 Extensions for Win32 / Internet Explorer URL handler) load is particularly relevant — it indicates the PowerShell process resolved a URL resource, consistent with the `Invoke-WebRequest` call targeting GitHub.

**Named pipe creation (Sysmon EID 17):** `\PSHost.134180063982908951.2068.DefaultAppDomain.powershell` was created, confirming the PowerShell host session was active.

**File creation (Sysmon EID 11):** `powershell.exe` (PID 2068) created `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-Interactive` — the PowerShell startup profile data file, not the HTA itself.

**PowerShell events (107 EID 4104, 3 EID 4103):** The PowerShell channel contains the standard test framework initialization blocks. The 4103 module logging events capture `Set-ExecutionPolicy` invocations.

## What This Dataset Does Not Contain

This dataset is missing the core technique artifacts that the defended variant contains. The defended dataset (35 Sysmon, 18 Security, 44 PowerShell, plus system and WMI events) records:

- Security EID 4688 showing PowerShell with the full command line including `Invoke-WebRequest`, the GitHub HTA URL, and the Startup folder write path
- Sysmon EID 1 for `mshta.exe` executing the downloaded HTA
- Sysmon EID 11 for the HTA file being written to `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\T1218.005.hta`
- Sysmon EID 3 (TCP connection to `185.199.109.133:443`) and EID 22 (DNS for `raw.githubusercontent.com`)

None of these are present in the undefended dataset. The undefended run captures only the PowerShell host initialization DLL loads and a standard file creation. This indicates the test's PowerShell invocation succeeded (the process started, loaded the runtime) but the actual technique commands — `Invoke-WebRequest` and `mshta.exe` invocation — were not captured in the available event samples.

The Cribl Edge collection or the Sysmon event buffer may have experienced a timing gap — the `urlmon.dll` load into PowerShell suggests network resolution was attempted, but the downstream process creation and network connection events fell outside the sample window.

## Assessment

This dataset does not provide useful technique-specific evidence. The undefended run captured only the PowerShell runtime initialization phase. The defended variant is the more complete dataset for this test, containing the full PowerShell command with technique arguments, the GitHub network connection, the HTA file write to Startup, and the `mshta.exe` process creation.

The notable difference between the two runs is that in the defended dataset, the `Invoke-WebRequest` failed with "Object reference not set to an instance of an object" (connectivity issue) — yet `mshta.exe` was still invoked against whatever content ended up in the HTA file. The undefended run's sparse evidence suggests either a similar connectivity failure or a collection gap.

If you are building detection content for this technique variant, the defended dataset's events provide the ground truth: look for PowerShell processes writing `.hta` files to Startup directories, followed by `mshta.exe` executing files from those paths.

## Detection Opportunities Present in This Data

**`urlmon.dll` loaded into PowerShell (Sysmon EID 7):** As in T1218.001-7, the presence of `urlmon.dll` in a PowerShell process's image load list indicates the process attempted URL resolution. Combined with the known technique behavior of downloading from GitHub, this serves as a precursor indicator.

**Sysmon EID 11 — HTA file written to Startup folder (from defended variant):** When visible, a `.hta` file created in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` by PowerShell or mshta.exe is a high-confidence persistence indicator. The combination of a remote download destination and a Startup folder write is directly detectable from file system telemetry.

**`mshta.exe` executing a file from a Startup directory (Sysmon EID 1, Security EID 4688):** The command line `mshta.exe "...\Startup\T1218.005.hta"` identifies both the execution vehicle (mshta) and the persistence mechanism (Startup folder HTA). Mshta executing files from user profile locations rather than application directories is a strong behavioral indicator.

**PowerShell `Invoke-WebRequest` to GitHub followed by file write to `%APPDATA%` and mshta invocation:** The three-step PowerShell behavior (web request → file write → mshta invoke) forms a detectable command sequence in PowerShell script block logging when the full technique runs.
