# T1560.001-1: Archive via Utility — Compress Data for Exfiltration With Rar

## Technique Context

T1560.001 covers Archive via Utility, where adversaries use dedicated archiving tools (RAR, 7-Zip, WinZip) to compress collected data prior to exfiltration. Unlike T1560-1 which uses a built-in PowerShell cmdlet, this test stages a third-party archiving tool. WinRAR (`Rar.exe`) is the specific utility used here, and its command-line interface (`rar a -r` to create a recursive archive) is a documented indicator seen in numerous intrusion cases including APT groups. Threat actors sometimes pre-stage WinRAR on victim systems or rely on it being already installed.

## What This Dataset Contains

The dataset spans 5 seconds (01:18:58–01:19:03 UTC) across 26 Sysmon events, 10 Security events, and 34 PowerShell events.

The ART test framework executes:
```
"cmd.exe" /c "%programfiles%/WinRAR/Rar.exe" a -r %USERPROFILE%\T1560.001-data.rar %USERPROFILE%\*.txt
```

Security 4688 and Sysmon EID 1 both capture the `cmd.exe` invocation with the full WinRAR command line — environment variables are expanded in the Security event: `"cmd.exe" /c "%%programfiles%%/WinRAR/Rar.exe" a -r %%USERPROFILE%%\T1560.001-data.rar %%USERPROFILE%%\*.txt`. The working directory is `C:\Windows\TEMP\`, consistent with the ART test framework behavior.

Security 4689 records `cmd.exe` exiting with status `0x1` — a non-zero exit code indicating failure. WinRAR was not present at `%ProgramFiles%/WinRAR/Rar.exe` on this system, so the RAR archive was never created. No Sysmon EID 11 file creation event for a `.rar` file appears, confirming the archive was not produced.

The ART `whoami.exe` preflight is captured in both Security 4688 and Sysmon EID 1. Sysmon EID 10 records the test framework PowerShell accessing the child processes. Two `\PSHost.*` pipes appear in Sysmon EID 17.

## What This Dataset Does Not Contain (and Why)

No `Rar.exe` process creation appears in Sysmon EID 1 or Security 4688. WinRAR is not installed on the test system (`ACME-WS02`). The `cmd.exe` wrapper attempted to invoke `%programfiles%/WinRAR/Rar.exe` but the binary was absent, causing the shell to exit with code `0x1`. This is a prerequisite failure, not a Defender block.

No `.rar` archive was created. No Sysmon EID 11 file creation for `T1560.001-data.rar` appears. No `.txt` files in the SYSTEM user profile were accessed or read.

This stands in contrast to T1560-1, where `Compress-Archive` succeeded because it uses Windows-native functionality that requires no external binary. The absence of the archiving tool is the critical difference between these two tests.

## Assessment

This dataset captures a prerequisite-failure scenario: the command line that would archive data with WinRAR is fully preserved in the telemetry, but execution stopped at the `cmd.exe` level because the tool was absent. The security value of this dataset is in demonstrating that the *command line itself* — the detection signal — is preserved regardless of whether the technique succeeds. A detection tuned on `Rar.exe a -r` in a command line would fire on the `cmd.exe` event here even though RAR never ran.

This is useful for training detectors that operate on Security 4688 command line content rather than requiring process creation of the archiving tool itself.

## Detection Opportunities Present in This Data

- **Security 4688**: `cmd.exe /c` invoking `WinRAR/Rar.exe a -r` with `%USERPROFILE%` as both archive destination and source; the `rar a -r` flag combination with user profile paths is a documented T1560.001 indicator.
- **Sysmon EID 1**: `cmd.exe` with the full WinRAR command line under SYSTEM context, parent `powershell.exe`; the `%programfiles%/WinRAR/Rar.exe` path resolves to the expected WinRAR installation path.
- **Security 4689**: `cmd.exe` exit status `0x1` within under a second of creation; combined with the WinRAR command line in the corresponding 4688, this exit code indicates the binary was missing rather than Defender blocking.
- **Absence of Rar.exe EID 1**: In a real attack where WinRAR *is* installed, Sysmon EID 1 would show `Rar.exe` as a child of `cmd.exe`; the absence here is a useful negative indicator for this specific system.
- **PowerShell 4103**: `Set-ExecutionPolicy Bypass` under SYSTEM, combined with the subsequent `cmd.exe /c Rar.exe` invocation, characterizes the full ART-style scripted archiving attempt.
- **Cross-technique comparison**: Comparing T1560-1 (PowerShell Compress-Archive, succeeded) with T1560.001-1 (WinRAR, failed) illustrates how native vs. external tool choice affects whether execution succeeds on a minimally provisioned system.
