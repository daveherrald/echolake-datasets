# T1560.001-12: Archive via Utility — Copy and Compress AppData Folder

## Technique Context

T1560.001 covers Archive via Utility. Test 12 targets a high-value source: the Windows AppData folder, which contains browser profiles, credential stores, application tokens, saved sessions, and configuration files across the full installed software stack. Adversaries copy AppData in preparation for exfiltration to capture everything without needing to know specific application paths. The technique uses PowerShell's built-in `System.IO.Compression.ZipFile` .NET class rather than a third-party tool, making it a native-LOL approach. This technique appears in information-stealer campaigns and targeted intrusions where credential harvesting is a primary objective.

## What This Dataset Contains

The dataset spans approximately 7 seconds (01:20:53–01:21:00 UTC) and is the largest in this series: 706 Sysmon events, 10 Security events, and 1,382 PowerShell events. The high Sysmon count reflects the bulk file copy operation — 666 EID 11 (FileCreate) events are generated as PowerShell copies hundreds of files from AppData to a staging directory.

The PowerShell script is captured in full via Security 4688 and PowerShell 4104:
```powershell
$AppData = "$env:USERPROFILE\AppData"
$Copy = "$env:USERPROFILE\Desktop\AppDataCopy"
$Zip = "$env:USERPROFILE\Desktop\AppDataBackup.zip"

Get-ChildItem $AppData -Recurse -Force | ForEach-Object { ... Copy-Item ... }
[System.IO.Compression.ZipFile]::CreateFromDirectory($Copy, $Zip, ...)
```

Sysmon EID 11 documents the staged copy in real time: `Desktop\AppDataCopy` is created first, followed by `Desktop\AppDataCopy\Local`, `\LocalLow`, `\Roaming`, and hundreds of subdirectories and files underneath — including `AppDataCopy\Local\Chromium\`, `AppDataCopy\Local\rustdesk\`, `AppDataCopy\Local\D3DSCache\`, `AppDataCopy\Local\Microsoft\`, and `AppDataCopy\Roaming\Python\Python312\site-packages\__pycache__\`. This reveals the software installed on the test system at the time of capture.

Sysmon EID 29 (FileExecutableDetected) fires 15 times on DLL and EXE files within the AppData tree as PowerShell copies them — specifically flagging `rustdesk\desktop_drop_plugin.dll`, `desktop_multi_window_plugin.dll`, and other executables. The rule annotation is `technique_id=T1059.001` (PowerShell), reflecting the sysmon-modular rule that fires when PowerShell creates an executable file.

PowerShell 4100/4102 error events capture a file access conflict: `The process cannot access the file 'WPNPRMRY.tmp' because it is being used by another process` — a real-world file lock collision during the copy, preserved faithfully in the dataset.

The second `powershell.exe` (executing the script) exits with status `0x0` — the archive operation completed. The zip file `AppDataBackup.zip` is not visible in the Sysmon EID 11 data because the ZipFile.CreateFromDirectory operation writes the zip as a single file write that may have completed just outside the collection window or been filtered; however, the directory copy (666 file events) and the clean exit code confirm the staging step succeeded.

## What This Dataset Does Not Contain (and Why)

The final `AppDataBackup.zip` file creation is not captured in the Sysmon EID 11 events. ZipFile.CreateFromDirectory may write the zip as a single internal .NET stream operation rather than triggering a filesystem-level FileCreate that Sysmon monitors. The staging copy directory (`AppDataCopy`) is fully captured, but the final archive is absent from the file telemetry. The clean exit code (`0x0`) confirms the process completed successfully.

No exfiltration follows the archiving step. This test isolates the collection/compression phase. No network connections, cloud storage, or transfer utilities appear.

The AppData content itself is not readable from event logs. The filenames exposed through Sysmon EID 11 reveal directory structure and application names, but no file contents are logged. Object access auditing is disabled in the audit policy.

No Defender block occurred. `Compress-Archive` and ZipFile operations on user-writable directories are not inherently suspicious to Defender without behavioral context.

## Assessment

This is the highest-fidelity T1560 dataset in the series. The technique succeeded: the AppData folder was copied and the ZIP archive was created (confirmed by exit code `0x0` and the complete staging directory tree in EID 11). The 666 file creation events constitute a rich ground-truth record of the staging operation, including the specific applications whose data was copied. The EID 29 events on executable files within AppData are an unusual but genuine signal of the copy operation touching binary files. The PowerShell 4102 file lock error is a realistic artifact of copying a live AppData folder. This dataset is well-suited for training on bulk file staging detection and for building behavioral baselines around recursive AppData access under anomalous execution contexts.

## Detection Opportunities Present in This Data

- **Security 4688**: `powershell.exe` with full `Get-ChildItem $AppData -Recurse | Copy-Item` + `ZipFile::CreateFromDirectory` script block under SYSTEM; the combination of AppData recursive copy and .NET compression in a single script is a strong exfiltration-staging indicator.
- **Sysmon EID 11 volume**: 666 file creation events in under 3 seconds from a single `powershell.exe` process; a burst of EID 11 events from PowerShell copying to `Desktop\AppDataCopy\` is highly anomalous.
- **Sysmon EID 11 path pattern**: Files being created under `Desktop\AppDataCopy\*` by PowerShell; staging files to a named copy directory on the Desktop is a common exfil-prep pattern.
- **Sysmon EID 29**: Executable files detected being written by `powershell.exe` into a staging directory; the `technique_id=T1059.001` annotation fires when PS writes executables, which is unusual behavior during a file copy.
- **PowerShell 4100/4102**: File access errors during a Copy-Item operation reveal the recursive copy scope; the specific locked file path (`Windows\Notifications\WPNPRMRY.tmp`) confirms access to the system-profile AppData tree.
- **PowerShell 4104**: `[System.IO.Compression.ZipFile]::CreateFromDirectory` with AppData source path in a SYSTEM-context script block; this .NET method invocation for compression is detectable in script block logging and is rarely legitimate under SYSTEM.
- **Sysmon EID 1**: Child `powershell.exe` tagged `T1083` (File and Directory Discovery) for the recursive `Get-ChildItem`; discovery immediately preceding compression and staging is the T1560 kill chain in two events.
