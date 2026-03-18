# T1560.001-12: Archive via Utility — Copy and Compress AppData Folder

## Technique Context

T1560.001 (Archive via Utility) applied to the Windows AppData folder targets one of the highest-value directories on any Windows endpoint. AppData contains browser profiles (with saved passwords, cookies, and session tokens), application credential stores, SSH/RDP configuration, VPN client configs, and authentication tokens for cloud services. An attacker who archives AppData captures the full installed-software credential surface without needing to know which specific applications are present.

This test uses PowerShell's `System.IO.Compression.ZipFile` .NET class — a native Windows capability that requires no external tools. The script first copies AppData to a staging directory on the Desktop, then compresses the staging copy into a ZIP archive. The two-step approach (copy then compress) avoids file-locking issues with open application files and produces a portable archive.

## What This Dataset Contains

The dataset spans 7 seconds (2026-03-17 17:33:54–17:34:01 UTC) and contains 1,068 PowerShell events, 4 Security events, and 499 Sysmon events — making this one of the larger datasets in the collection.

The full attack script is captured in Security EID 4688:
```powershell
"powershell.exe" & {$AppData="$env:USERPROFILE\AppData"
$Copy="$env:USERPROFILE\Desktop\AppDataCopy"
$Zip="$env:USERPROFILE\Desktop\AppDataBackup.zip"

if (Test-Path $Copy) { Remove-Item $Copy -Recurse -Force }
New-Item -ItemType Directory -Path $Copy | Out-Null

Get-ChildItem $AppData -Recurse -Force | ForEach-Object { [copy logic] }
[System.IO.Compression.ZipFile]::CreateFromDirectory($Copy, $Zip...)
```

The destination paths are `$env:USERPROFILE\Desktop\AppDataCopy` (staging directory) and `$env:USERPROFILE\Desktop\AppDataBackup.zip` (final archive). Running as SYSTEM, `$env:USERPROFILE` resolves to `C:\Windows\System32\config\systemprofile`.

Security EID 4688 records 4 process creation events: two `whoami.exe` checks, the attack `powershell.exe`, and a cleanup `powershell.exe` (`& {}` — empty block, confirming the cleanup was a no-op in this run).

Sysmon EID 1 captures 4 process creation events with full hashes and parent-child chains, including the attack PowerShell tagged `RuleName: technique_id=T1059.001,technique_name=PowerShell`. The cleanup PowerShell shows `CommandLine: "powershell.exe" & {}`.

**Sysmon EID 11 dominates the dataset with 463 FileCreate events.** These events document each individual file written to the staging directory (`$env:USERPROFILE\Desktop\AppDataCopy`) as PowerShell copies files from AppData one by one. Each file copy generates a TargetFilename entry under the staging path. This volume of FileCreate events reveals the breadth of the staging operation — hundreds of files copied from AppData in under 7 seconds.

Sysmon EID 7 records 25 ImageLoad events for the PowerShell DLL load chains. Sysmon EID 10 records 4 ProcessAccess events. Sysmon EID 17 records 3 named pipe creation events.

The PowerShell events break down to 940 EID 4103 (module logging), 120 EID 4104 (script block logging), 4 EID 4102, and 4 EID 4100 events. The 940 module logging events reflect `Get-ChildItem -Recurse -Force` iterating over AppData followed by `ForEach-Object { Copy-Item }` for each file — PowerShell generates a 4103 event for each pipeline element processed.

## What This Dataset Does Not Contain

No Sysmon EID 11 event for the final ZIP file (`AppDataBackup.zip`). The archive creation via `[System.IO.Compression.ZipFile]::CreateFromDirectory()` produces a ZIP file, but no FileCreate event for it appears — the Sysmon filter either did not match the `.zip` extension or the file was written via a code path that bypasses the file system filter driver's create notification in this context.

No Security 4688 events for the intermediate copy operations. The `Copy-Item` calls within `ForEach-Object` run entirely within the PowerShell process — no child processes are spawned, so no 4688 events appear for file copy activity. The 463 Sysmon EID 11 events are the only record of the individual file copies.

No content of the archived files is recorded. AppData may contain password databases, browser profiles, and authentication tokens, but Windows event logging does not capture file content. The dataset shows that the files were copied but not what data they contained.

Compared to the defended variant (706 Sysmon, 10 Security, 1,382 PowerShell), the undefended run produced fewer total events. The defended variant had 706 Sysmon events versus 499 here, and 1,382 PowerShell events versus 1,068 here. The reduction suggests Defender's file scanning activity in the defended run generated additional telemetry — particularly additional EID 11 FileCreate events as Defender scanned the staged files.

## Assessment

This dataset captures the most forensically complete execution among the T1560 series. The 463 Sysmon EID 11 events documenting individual file copies from AppData provide a near-complete record of what was staged. Correlation of the TargetFilename values against known credential store paths (browser profile directories, SSH key locations, token cache paths) can reveal the scope of sensitive data captured.

The technique succeeds here because `Compress-Archive` and `System.IO.Compression.ZipFile` are native Windows functionality — no executable staging is required and Defender has no file-based signature to match.

The staging directory (`AppDataCopy`) creates a forensic artifact on the Desktop. In a real intrusion, the archive would be exfiltrated and the staging directory removed; this dataset captures the window between archive creation and cleanup.

## Detection Opportunities Present in This Data

**Sysmon EID 11 volume**: 463 FileCreate events from `powershell.exe` writing to a path under `$env:USERPROFILE\Desktop\AppDataCopy\` within a 7-second window is anomalous. Any detection logic that triggers on a PowerShell process creating more than a threshold number of files in a short window — especially when the destination path contains "AppData" in the source and a Desktop subdirectory in the destination — is well-positioned to catch this.

**Security EID 4688 / Sysmon EID 1 command line**: The `[System.IO.Compression.ZipFile]::CreateFromDirectory` pattern in the PowerShell command line is specific to this technique. Legitimate applications typically use this via compiled code rather than inline in a command-line invocation.

**Staging path pattern**: Writes to `$env:USERPROFILE\Desktop\AppDataCopy\` and `$env:USERPROFILE\Desktop\AppDataBackup.zip` from a SYSTEM-context PowerShell process are high-confidence indicators. A user's Desktop is not a typical destination for system-level file operations.

**Parent-child chain**: `powershell.exe` (SYSTEM) spawning `powershell.exe` with an inline script block referencing AppData is visible in both Security 4688 and Sysmon EID 1. The PowerShell-spawns-PowerShell pattern under SYSTEM, combined with AppData access, narrows the field of legitimate explanations significantly.
