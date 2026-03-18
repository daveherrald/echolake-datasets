# T1547.014-1: Active Setup — Active Setup - HKLM Add atomic_test Key to Launch Executable

## Technique Context

T1547.014 (Active Setup) exploits the Windows Active Setup mechanism, which is designed to run per-user initialization tasks when a user logs on for the first time after a per-machine software installation. Active Setup entries live under `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\`. Each subkey can contain a `StubPath` value pointing to an executable; if the version counter for that key is higher in HKLM than in the user's HKCU, Windows runs the `StubPath` executable on next logon. This is a persistence technique that runs in user context (not SYSTEM) and triggers when any new user logs on to the machine, making it attractive for lateral movement scenarios. It is implemented through `runonce.exe /AlternateShellStartup` which processes the Active Setup entries.

## What This Dataset Contains

The test creates a new Active Setup key named `atomic_test` with a `StubPath` pointing to `calc.exe`, then immediately invokes `runonce.exe /AlternateShellStartup` to trigger execution. The PowerShell EID 4104 script block is captured in full:

```powershell
New-Item "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components" -Name "atomic_test" -Force
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\atomic_test"
  "(Default)" "ART TEST" -Force
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\atomic_test"
  "StubPath" "C:\Windows\System32\calc.exe" -Force
& $env:SYSTEMROOT\system32\runonce.exe /AlternateShellStartup
```

Sysmon EID 1 captures `whoami.exe` (T1033), the PowerShell process (T1083), and `runonce.exe` (T1083):

```
Process Create:
  Image: C:\Windows\System32\runonce.exe
  CommandLine: "C:\Windows\system32\runonce.exe" /AlternateShellStartup
  User: NT AUTHORITY\SYSTEM
```

Sysmon EID 11 captures a file created by `runonce.exe` with the tag `technique_id=T1574.010`:
```
File created:
  Image: C:\Windows\system32\runonce.exe
  TargetFilename: C:\Windows\System32\config\systemprofile\AppData\Local\
                  Microsoft\Windows\Explorer\ExplorerStartupLog...
```
This is the Explorer startup log that `runonce.exe` writes as part of its processing.

Sysmon event counts: 41 events across EID 1 (3), EID 7 (28), EID 10 (3), EID 11 (4), EID 17 (3). No EID 13 events — the sysmon-modular configuration does not have a rule covering the Active Setup Installed Components key path.

Security events: 14 events (4688 × 4, 4689 × 9, 4703 × 1). Security EID 4688 records capture `whoami.exe`, the PowerShell process, `runonce.exe`, and `calc.exe` (triggered by the Active Setup `StubPath`).

## What This Dataset Does Not Contain

**Sysmon EID 13 is absent.** The sysmon-modular configuration has no rule matching `SOFTWARE\Microsoft\Active Setup\Installed Components`. The registry key creation and `StubPath` value write are not captured in Sysmon. Detection for the persistence registration phase relies entirely on PowerShell script block logging.

**calc.exe process creation in Sysmon EID 1 is absent** — the Sysmon include-mode ProcessCreate filter does not match `calc.exe` as a suspicious process. However, `calc.exe` does appear in Security EID 4688, confirming that the `StubPath` was actually executed by `runonce.exe`.

**The Active Setup HKCU update** — when runonce processes Active Setup, it writes a mirrored key to HKCU to mark the component as initialized. This HKCU write is not captured in Sysmon (no EID 13 rule for HKCU Active Setup) and Security object access auditing is disabled.

## Assessment

The test ran to completion, including `runonce.exe` actually executing the `StubPath` (`calc.exe`). The full persistence chain — registry write, then triggered execution — is confirmed by the PowerShell script block and Security EID 4688 for calc.exe. The absence of Sysmon EID 13 for the Active Setup key is a detection gap, but the `runonce.exe /AlternateShellStartup` invocation combined with the script block provides strong detection opportunity.

## Detection Opportunities Present in This Data

- **PowerShell EID 4104**: The `New-Item` and `Set-ItemProperty` calls targeting `Active Setup\Installed Components` with a `StubPath` value are fully captured. Alerting on PowerShell writing `StubPath` under Active Setup is high-confidence.
- **Sysmon EID 1 / Security EID 4688**: `runonce.exe /AlternateShellStartup` is rarely invoked legitimately outside of domain-joined machines running enterprise software deployment. This command line alone is a useful alert trigger.
- **Security EID 4688**: `calc.exe` spawned as a child of `runonce.exe` with no interactive user context is anomalous — a sign that the Active Setup trigger fired successfully.
- A Sysmon EID 12/13 rule for `SOFTWARE\Microsoft\Active Setup\Installed Components` would significantly improve detection coverage for this technique and should be added to the monitoring configuration.
- The process chain `powershell.exe` → `runonce.exe /AlternateShellStartup` → unexpected child process (`calc.exe`) is a three-event correlation that uniquely identifies this persistence technique variant.
