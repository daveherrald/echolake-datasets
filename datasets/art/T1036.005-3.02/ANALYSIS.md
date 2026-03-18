# T1036.005-3: Match Legitimate Resource Name or Location — Masquerading cmd.exe as VEDetector.exe

## Technique Context

T1036.005 (Match Legitimate Resource Name or Location) is a masquerading technique where adversaries name malicious files after legitimate security tools or system utilities to appear benign when observed in process lists, file system scans, or logs. This test copies `cmd.exe` to `$env:TEMP\VEDetector.exe`, creates a registry run key at `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\VEDetector` pointing to the temp binary, and executes it. The name `VEDetector.exe` mimics a security product scanner, a pattern adversaries use because users and analysts may recognize and trust security tool names.

The addition of a registry run key for persistence distinguishes this test from the simpler rename tests in the T1036.003 series. Here the masquerade serves a persistence goal: the renamed binary will execute at every user logon under an innocuous-sounding name. Attackers frequently combine T1036.005 (name mimicry) with T1547.001 (registry run key persistence) precisely because the deceptive name reduces the likelihood that the run key entry will be flagged during routine security review.

Detection targets include: the run key addition to `HKLM\...\Run`, process execution from `$env:TEMP` under a security-tool-like name, file creation events for executables in temp directories, and the mismatch between the binary's `OriginalFileName` (`Cmd.Exe`) and the running name (`VEDetector.exe`).

## What This Dataset Contains

This dataset contains 146 events: 99 PowerShell events, 6 Security events, 40 Sysmon events, 1 Application event, and 1 Task Scheduler event.

The Security channel (EID 4688) tells the story concisely. The main attack command is a multi-step PowerShell invocation: `Copy-Item -Path "$env:SystemRoot\System32\cmd.exe" -Destination "$env:TEMP\VEDetector.exe" -Force`, then `New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "VEDetector" -Value "$env:TEMP\VEDetector.exe" -PropertyType String -Force`, then `Start-Process -FilePath "$env:TEMP\VEDetector.exe"`. The masqueraded process appears: `CommandLine: "C:\Windows\TEMP\VEDetector.exe"`, `NewProcessName: C:\Windows\Temp\VEDetector.exe`, `ParentProcessName: powershell.exe`. The cleanup invocation removes the registry key, stops the process, and deletes the file.

EID 4702 (scheduled task updated) for `\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask` is background OS activity coinciding with the test.

Sysmon provides rich telemetry here. EID 7 image loads show the standard .NET and Defender DLL chain for the test framework PowerShell. EID 10 (process access) shows `powershell.exe` accessing `whoami.exe` and itself. EID 17 (named pipe create) records PowerShell hosting pipes. EID 11 (file create) captures `powershell.exe` creating `C:\Windows\Temp\VEDetector.exe` and `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-Interactive`. EID 13 (registry write) events capture the `HKLM:\Software\Microsoft\Windows\CurrentVersion\Run\VEDetector` key being set — the persistence mechanism. EID 29 (file executable detected) fires on the new `VEDetector.exe` binary.

Compared to the defended dataset (43 Sysmon, 14 Security, 41 PowerShell), the undefended version has very similar counts, as expected: `cmd.exe` renamed to a non-threatening-looking name would not be blocked by Defender in either case. The primary behavioral difference is that the masqueraded process executes for 5 seconds (`Start-Sleep -Seconds 5` in the command) before cleanup.

## What This Dataset Does Not Contain

The Sysmon EID 13 registry write event for the `Run` key is present in the samples but the full registry key value (the path to `VEDetector.exe`) should be visible in the `Details` field. Sysmon EID 1 does not capture the `VEDetector.exe` process execution itself, so the `OriginalFileName: Cmd.Exe` discrepancy is not visible from Sysmon in this dataset — only from Security EID 4688.

No child processes from the masqueraded `cmd.exe` running as `VEDetector.exe` are captured — it ran interactively for 5 seconds but issued no commands visible in the telemetry.

## Assessment

This dataset is particularly valuable for testing combined masquerade-plus-persistence detection. The Sysmon EID 13 registry write to `HKLM\...\Run\VEDetector` combined with the file creation event (EID 11) for `$env:TEMP\VEDetector.exe` and the subsequent process execution from that path represents a complete attack chain: drop, persist, execute. The dataset cleanly demonstrates what this chain looks like in the absence of Defender interference. Detection engineers building rules for run-key additions pointing to temp directory executables should find this dataset directly useful.

## Detection Opportunities Present in This Data

1. Sysmon EID 13 (registry set value) for `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\<name>` where the value points to a path in `$env:TEMP`, `$env:APPDATA`, or other writable directories is the primary persistence detection.

2. Sysmon EID 11 (file create) for an executable written to `$env:TEMP` with a name that does not match known Windows binaries but resembles security tool names (e.g., containing `Detector`, `Scanner`, `Monitor`, `AV`) warrants investigation.

3. EID 4688 for a process running from `C:\Windows\Temp\VEDetector.exe` (or any similar security-tool-mimicking name in a temp directory) with parent `powershell.exe` is anomalous — legitimate security tools don't run from temp directories with PowerShell as their parent.

4. The temporal sequence of Sysmon EID 11 (executable dropped to temp) → EID 13 (run key written pointing to that temp path) → EID 4688 (process executed from temp path) within a single PowerShell session is a high-confidence behavioral indicator of the full masquerade-plus-persistence pattern.

5. Sysmon EID 29 (file executable detected) in `$env:TEMP` for a file with a security-product-like name, combined with a contemporaneous registry run key creation, provides a correlated multi-event signature.

6. PowerShell EID 4104 script blocks containing `New-ItemProperty` targeting `HKLM:\Software\Microsoft\Windows\CurrentVersion\Run` combined with `Copy-Item` from a Windows system directory to a temp path should be flagged as a persistence-setup pattern.
