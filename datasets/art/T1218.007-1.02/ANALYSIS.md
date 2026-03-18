# T1218.007-1: Msiexec — Execute Local MSI File with Embedded JScript

## Technique Context

T1218.007 (Msiexec) describes adversary abuse of the Windows Installer service binary (`msiexec.exe`) to proxy execution of malicious code. Msiexec is a trusted, signed Microsoft binary present on every Windows system. Attackers craft MSI packages containing custom actions — embedded scripts (JScript, VBScript) or executables — that run during the installation process with the privileges of `msiexec.exe`. This makes it an effective Living off the Land Binary (LOLBin) for bypassing application control solutions that trust signed Microsoft binaries by default.

This test uses a locally pre-staged MSI file (`T1218.007_JScript.msi`) that contains an embedded JScript custom action. The MSI is invoked quietly (`/q`) in install mode (`/i`), causing `msiexec.exe` to execute the embedded JScript without any user interaction or visible UI.

Application control products such as AppLocker and Windows Defender Application Control (WDAC) typically allow `msiexec.exe` to run, and the MSI packaging format provides a legitimate-looking container for the malicious payload.

The dataset was collected on ACME-WS06 (Windows 11 Enterprise, domain-joined to acme.local) with Windows Defender disabled.

## What This Dataset Contains

The dataset spans a brief window in March 2026 and contains 129 total events: 96 PowerShell, 11 Security, 20 Sysmon, and 2 Application.

**The complete attack chain is preserved.** Security EID 4688 captures all process creations with full command lines:

1. `"cmd.exe" /c c:\windows\system32\msiexec.exe /q /i "C:\AtomicRedTeam\atomics\T1218.007\bin\T1218.007_JScript.msi"` — cmd.exe launched by PowerShell
2. `c:\windows\system32\msiexec.exe /q /i "C:\AtomicRedTeam\atomics\T1218.007\bin\T1218.007_JScript.msi"` — msiexec.exe performing the install
3. `C:\Windows\system32\msiexec.exe /V` — secondary msiexec process (version check)
4. `C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s WdiSystemHost` — diagnostic service activity
5. `"C:\Windows\system32\whoami.exe"` — execution twice, confirming the JScript payload ran

**Sysmon EID 1** captures the core process chain with parent-child relationships:
- `powershell.exe` (test framework) → `cmd.exe` (`CommandLine: "cmd.exe" /c c:\windows\system32\msiexec.exe /q /i "C:\AtomicRedTeam\atomics\T1218.007\bin\T1218.007_JScript.msi"`, `RuleName: technique_id=T1059.003`)
- `cmd.exe` → `msiexec.exe` (`CommandLine: c:\windows\system32\msiexec.exe /q /i "C:\AtomicRedTeam\atomics\T1218.007\bin\T1218.007_JScript.msi"`, `RuleName: technique_id=T1218`)
- `whoami.exe` executions confirming payload delivery

**Sysmon EID 10 (Process Access)** records PowerShell accessing `whoami.exe` and `cmd.exe` with `GrantedAccess: 0x1fffff`, tagged `technique_id=T1055.001`.

**Application EID 1040 and 1042** represent the Windows Installer transaction start and end events, confirming the MSI was processed by the Windows Installer infrastructure.

**Security EID 4672 and 4624** record logon and privilege events associated with the msiexec session, providing account context for the installation.

**PowerShell EID 4104** captures 95 events. Key content includes `Set-ExecutionPolicy Bypass -Scope Process -Force` and `$ErrorActionPreference = 'Continue'` (test framework setup), and a cleanup scriptblock: `Invoke-AtomicTest T1218.007 -TestNumbers 1 -Cleanup -Confirm:$false 2>&1 | Out-Null`.

## What This Dataset Does Not Contain

The embedded JScript payload's specific content is not captured in the PowerShell or Sysmon channels. The JScript runs inside the `msiexec.exe` process as a custom action and is not subject to PowerShell script block logging. What runs inside the MSI custom action is opaque to these telemetry channels — only its effects (the `whoami.exe` spawning) are visible.

No Sysmon EID 3 (network connection) events appear, consistent with a local MSI installation requiring no network communication.

No Sysmon EID 11 file creation events from the malicious payload appear. The MSI extraction artifacts (`.tmp` files in `C:\Windows\Installer\`) are not in this dataset's sample window.

The defended variant of this test (T1218.007-1, defended) reported msiexec exiting with error code 0x653 (ERROR_INSTALL_PACKAGE_OPEN_FAILED), indicating Defender blocked the MSI. In this undefended dataset, the technique succeeds fully — both `whoami.exe` executions confirm the JScript custom action ran.

## Assessment

This dataset provides clean, complete telemetry for a successful undefended Msiexec LOLBin execution with an embedded JScript payload. The full process chain from PowerShell test framework through cmd.exe to msiexec.exe is preserved with command-line arguments intact. The Windows Installer application log entries confirm MSI processing. The `whoami.exe` executions confirm payload execution.

Compared to the defended variant (19 Sysmon, 23 Security, 34 PowerShell, 2 Application), this undefended run produced fewer Security events (11 vs. 23) because Defender's blocking behavior in the defended run generated additional privilege and access events. The undefended run succeeds cleanly with less noise.

## Detection Opportunities Present in This Data

**Security EID 4688:** The command line `c:\windows\system32\msiexec.exe /q /i "C:\AtomicRedTeam\atomics\T1218.007\bin\T1218.007_JScript.msi"` is directly actionable. Key signals: `msiexec.exe` invoked with `/q /i` (quiet install) from a non-standard path, with the MSI residing in `C:\AtomicRedTeam\`. In real intrusions, look for msiexec `/ q /i` pointing to temp directories, user profiles, or network paths.

**Sysmon EID 1:** The process chain `powershell.exe → cmd.exe → msiexec.exe` with the quiet-install MSI path is captured and tagged by sysmon-modular rules (`technique_id=T1218`, `technique_id=T1059.003`). The parent-child relationship from PowerShell through cmd to msiexec is unusual for legitimate software installation, which typically comes from installers, package managers, or GPO-driven deployment.

**Application EID 1040/1042:** Windows Installer transaction events confirm MSI execution and can be correlated with Security 4688 to establish the timeline. These events include the installer package name, which in a real attack would be an attacker-controlled string.

**Sysmon EID 10:** Full-access process access from PowerShell to `cmd.exe` and `whoami.exe` is tagged `technique_id=T1055.001`. While the access pattern here is the ATH framework's standard monitoring approach, similar process access patterns from unexpected parents warrant attention.
