# T1574.001-6: DLL — DLL Search Order Hijacking, DLL Sideloading of KeyScramblerIE.DLL via KeyScrambler.EXE

## Technique Context

T1574.001 (Hijack Execution Flow: DLL Search Order Hijacking) includes DLL side-loading through legitimate third-party software installers. `KeyScrambler` is a commercial keystroke encryption tool. Its main executable (`KeyScrambler.exe`) loads `KeyScramblerIE.dll` from its installation directory by relative path. An attacker who can place a malicious `KeyScramblerIE.dll` in that directory — or who redirects execution to a writable location — can cause the legitimate signed binary to load attacker-controlled code.

This test downloads and installs KeyScrambler from the official vendor website, then copies `KeyScrambler.exe` to a temporary directory and attempts to execute it, demonstrating that the installation places world-readable DLLs in a path where side-loading is possible.

## What This Dataset Contains

The dataset captures 120 events across Sysmon (4), Security (59), PowerShell (55), and System (2) logs collected over approximately 14 seconds on ACME-WS02.

**This is the most elaborate test in the T1574.001 group, involving real software installation:**

PowerShell Event 4103 (Module Logging) captures the full attack script execution:
- `Invoke-WebRequest -Uri "https://download.qfxsoftware.com/download/latest/KeyScrambler_Setup.exe"` — live download from vendor
- `Start-Process "C:\Windows\TEMP\KeyScrambler_Setup.exe" /S` — silent installation
- `Copy-Item ... "C:\Windows\TEMP\KeyScrambler.exe"` — copying the executable to TEMP
- `Start-Process "C:\Windows\TEMP\KeyScrambler.exe"` — attempting to execute from TEMP

Security Event 4688 records the full KeyScrambler installation chain:
- `KeyScrambler_Setup.exe /S` — silent installer
- Multiple `regsvr32.exe` invocations registering `KeyScramblerIE.dll`
- `icacls keyscrambler\KeyScramblerIE.dll /grant everyone:RX` — setting world-readable permissions
- Multiple `DriverInstaller.exe` invocations (`/ulogon`, `/i`, `/uupdater`, `/iupdater`)

Sysmon Event 22 (DNS Query) captures:
- `download.qfxsoftware.com` resolved by `powershell.exe`

Sysmon Event 3 (Network Connection) records outbound connections from `powershell.exe` and `MsMpEng.exe` (Defender scanning the download).

System Event 7045 records two new services installed:
- `KeyScrambler` — `System32\DRIVERS\keyscrambler.sys`
- `QFX Software Update Service` — `C:\Program Files (x86)\KeyScrambler\...`

PowerShell Event 4100 (Error) records a termination error on `Start-Process` for `KeyScrambler.exe`, indicating Defender blocked the final execution step.

## What This Dataset Does Not Contain (and Why)

**The DLL side-load did not succeed.** `Start-Process "C:\Windows\TEMP\KeyScrambler.exe"` failed with a terminating error (PowerShell Event 4100), meaning Defender blocked execution of the copied binary before it could load `KeyScramblerIE.dll` from the TEMP directory.

**No Sysmon Event 7 for DLL loads.** The Sysmon include-mode filter did not trigger for the KeyScrambler processes (they are not on the suspicious pattern list). The only Sysmon events present are network-related (Event 3, 22).

**No Sysmon Event 1 for the installer or KeyScrambler.exe.** Again, the include-mode filter means only pre-approved suspicious process patterns generate Event 1 in Sysmon. The Security log provides complementary 4688 coverage.

**No malicious DLL payload execution.** The test uses the legitimate vendor DLL; the scenario demonstrates the susceptibility path but does not deploy a custom malicious payload.

## Assessment

This dataset is distinct from others in the group because it involves genuine network activity, real software installation, and driver installation — producing significantly richer Security and PowerShell telemetry. It represents a realistic supply-chain-adjacent attack vector: an adversary who installs legitimate software to enable a side-load opportunity. The DNS query to the vendor domain, installer chain, and service/driver registration are all observable and detectable. Defender blocked the final execution step, but all prerequisite activity is fully logged.

## Detection Opportunities Present in This Data

- **Sysmon Event 22**: DNS resolution of `download.qfxsoftware.com` by `powershell.exe` — PowerShell directly initiating downloads from software vendor domains.
- **Sysmon Event 3**: Outbound network connection from `powershell.exe` — direct HTTP/HTTPS from PowerShell to internet hosts.
- **System Event 7045**: Two new services installed within the same session — kernel driver (`keyscrambler.sys`) plus updater service; driver installation from a user-initiated process warrants review.
- **Security Event 4688**: `regsvr32.exe` registering DLLs spawned by an installer process from `C:\Windows\TEMP\` — installer in TEMP directory is anomalous.
- **Security Event 4688**: `icacls` granting `everyone:RX` on a DLL — explicit world-readable permission grant on a DLL is a side-loading enablement indicator.
- **PowerShell Event 4103**: Full `Invoke-WebRequest`, `Start-Process` chain logged with module logging — the attack script is fully reconstructable from PowerShell logs.
- **PowerShell Event 4100**: Error on `Start-Process KeyScrambler.exe` — Defender block is visible as a PowerShell terminating error.
