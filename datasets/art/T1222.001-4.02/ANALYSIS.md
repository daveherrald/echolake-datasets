# T1222.001-4: Windows File and Directory Permissions Modification — attrib hide file

## Technique Context

T1222.001 covers adversary use of Windows file attribute manipulation to conceal files from casual inspection. The `attrib.exe` utility with the `+h` flag sets the hidden attribute on a file, removing it from standard directory listings and GUI folder views. While technically trivial — the file remains accessible to any process that explicitly requests hidden files — this technique is a persistent component of malware toolkits used to hide dropped payloads, persistence mechanisms, configuration files, and exfiltration staging directories.

Test T1222.001-4 creates two text files in `%TEMP%\T1222.001_attrib_2\` and then sets the hidden attribute on both using `attrib.exe +h`. The ART cleanup step subsequently deletes the hidden files using `del /A:H`, which targets hidden files specifically. In the defended variant, Windows Defender allowed the execution (file hiding is not blocked by AV); in this undefended dataset, the behavior is identical since Defender would not have intervened in either run.

## What This Dataset Contains

This dataset captures the complete execution: file creation, hidden attribute setting on two files, and the cleanup deletion. All key steps are present across three channels.

**Security EID 4688** records the full process chain. PowerShell (running as `NT AUTHORITY\SYSTEM`) spawns `cmd.exe` with this compound command:

```
"cmd.exe" /c mkdir %temp%\T1222.001_attrib_2 >nul 2>&1 & echo T1222.001_attrib1 >> %temp%\T1222.001_attrib_2\T1222.001_attrib1.txt & echo T1222.001_attrib2 >> %temp%\T1222.001_attrib_2\T1222.001_attrib2.txt & attrib.exe +h %temp%\T1222.001_attrib_2\T1222.001_attrib1.txt & attrib.exe +h %temp%\T1222.001_attrib_2\T1222.001_attrib2.txt
```

Individual EID 4688 events capture each child process: two `attrib.exe` processes with command lines `attrib.exe +h C:\Windows\TEMP\T1222.001_attrib_2\T1222.001_attrib1.txt` and `attrib.exe +h C:\Windows\TEMP\T1222.001_attrib_2\T1222.001_attrib2.txt`. The cleanup phase is also captured: a second `cmd.exe` invocation with `del /A:H %temp%\T1222.001_attrib_2\T1222.001_attrib*.txt`.

Six total Security EID 4688 events document the full chain: the initial `whoami.exe` preflight, the compound `cmd.exe` with the mkdir/echo/attrib sequence, both individual `attrib.exe` invocations, the cleanup `cmd.exe`, and paired `whoami.exe` invocations from the test framework.

**Sysmon EID 1** (ProcessCreate) captures the cmd.exe and attrib.exe process creations with hashes. The sysmon-modular rules tag the attrib.exe events with `technique_id=T1564.001,technique_name=Hidden Files and Directories` — a direct behavioral match. The cleanup `cmd.exe` spawn with `/A:H` (delete hidden files) is also captured.

**Sysmon EID 11** (FileCreate) records two file creation events: a Defender scan artifact (`C:\Windows\Temp\01dcb62fa169b9bb`, written by `MsMpEng.exe` during its background scanning activity) and the PowerShell startup profile write (`C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-Interactive`). Note that the technique's own target files (`T1222.001_attrib1.txt` and `T1222.001_attrib2.txt`) do not appear as separate Sysmon EID 11 events in the samples, because they are written by `echo` redirected inside the `cmd.exe` compound command, and the sysmon-modular filter does not match temp text files written via cmd echo redirection.

The Application channel contains one EID 15 event (Application Error / Windows Error Reporting registration), which is background noise unrelated to the technique.

The PowerShell channel (107 events: 104 EID 4104 + 3 EID 4103) contains only ART test framework boilerplate. The actual technique is executed by cmd.exe and attrib.exe, not by PowerShell scripting.

**Compared to the defended variant** (20 Sysmon / 14 Security / 32 PowerShell): The undefended run is modestly larger (25 Sysmon / 6 Security / 107 PowerShell). The higher PowerShell count in the undefended run reflects the same test framework infrastructure. Security event counts are lower (6 vs. 14) in the undefended run, which is unexpected — the defended variant appears to have generated more process creation/termination activity. Since Defender does not block attrib.exe usage, the core technique behavior is present in both variants. The principal value of this undefended dataset is confirmation that the full execution completes cleanly.

## What This Dataset Does Not Contain

The dataset does not include Security EID 4656/4663 (object access audit) events showing the file attribute change itself. Object access auditing is not enabled in this environment, so there is no per-file evidence of the hidden attribute being set — only the `attrib.exe` process invocation. There are no before/after directory listing events showing the file appearing hidden. The Application channel EID 15 event is unrelated to the technique and provides no attribution value. The PowerShell channel contains no technique-specific content.

## Assessment

This is a clean, complete execution dataset for the attrib hidden-file technique. The compound `cmd.exe` command line in Security EID 4688 contains the full sequence from directory creation through attribute setting, giving you the complete operational picture in a single event. Individual `attrib.exe` command lines with explicit `+h` flags are captured in both Security and Sysmon channels. The Sysmon rule tagging (`T1564.001`) is correctly applied, confirming the behavioral ruleset fires on this technique. The cleanup deletion with `del /A:H` is a secondary indicator that something was hidden before being removed.

## Detection Opportunities Present in This Data

- **Sysmon EID 1**: `attrib.exe +h` command lines with temp directory paths. The sysmon-modular config already matches this with rule name `technique_id=T1564.001,technique_name=Hidden Files and Directories`.
- **Security EID 4688**: `attrib.exe` with `+h` argument against files in `%TEMP%` or other staging directories. The explicit file paths in the command line identify both the target directory and the files being hidden.
- **Security EID 4688**: The compound `cmd.exe` command line contains the mkdir, echo, and attrib sequence — a behavioral cluster that suggests tool deployment followed by hiding, which is more significant than any single command.
- **Sysmon EID 1**: `del /A:H` in a `cmd.exe` command line following an `attrib +h` sequence — cleanup of hidden files is consistent with tool-drop-and-erase patterns used by loaders and droppers.
