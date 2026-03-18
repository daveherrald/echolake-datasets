# T1542.001-1: Pre-OS Boot — System Firmware (UEFI Persistence via Wpbbin.exe File Creation)

## Technique Context

T1542.001 (System Firmware) covers adversary persistence and defense evasion through UEFI/BIOS firmware implants. True firmware implants are among the most sophisticated and durable persistence mechanisms available, surviving OS reinstalls and disk replacements. The `Wpbbin.exe` variant is a Windows-specific UEFI persistence mechanism: legitimate Windows BIOS-based boot firmware can drop `%SystemRoot%\System32\wpbbin.exe` at first boot, and Windows will automatically execute it during startup. APT groups — notably those attributed to nation-state actors — have abused this mechanism by writing malicious content to the UEFI and configuring it to drop a malicious `wpbbin.exe` on boot. The file's presence in `System32` is itself suspicious on systems without qualifying UEFI firmware, making it a reliable indicator.

Detection focuses on: the creation of `wpbbin.exe` in `%SystemRoot%\System32\` by unexpected processes, and process execution of `wpbbin.exe` at system startup.

## What This Dataset Contains

The ART test simulates the filesystem artifact of this technique — it creates an empty `wpbbin.exe` file in `C:\Windows\System32\` using PowerShell's `New-Item` cmdlet, without actually modifying UEFI firmware:

```powershell
New-Item -ItemType File -Path "$env:SystemRoot\System32\wpbbin.exe"
```

Sysmon Event ID 11 (FileCreate) records this action:

```
TargetFilename: C:\Windows\System32\wpbbin.exe
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: NT AUTHORITY\SYSTEM
```

PowerShell Event ID 4104 (Script Block Logging) captures the full script block including the `New-Item` call and the `echo "Creating %systemroot%\wpbbin.exe"` output. Event ID 4103 (Module Logging) records `Write-Output` and `New-Item` parameter bindings — the latter showing `name="Path"; value="C:\Windows\System32\wpbbin.exe"` explicitly.

Security 4688 records the `powershell.exe` child process with the command line. All processes exited `0x0`, confirming the file was created successfully (SYSTEM has write access to System32).

Sysmon Event ID 1 records the parent-child chain: outer `powershell.exe` (test framework) → inner `powershell.exe` (technique script).

## What This Dataset Does Not Contain

**No UEFI or firmware modification.** This test only simulates the file-drop artifact. No actual UEFI write occurred; there is no event telemetry for firmware access, UEFI variable writes, or boot configuration changes. Real UEFI firmware implants would not produce Windows event log telemetry at all at the firmware level.

**No execution of wpbbin.exe.** The created file is empty; it is never executed. No process creation events for `wpbbin.exe` appear. A complete dataset would include the file's execution at next boot startup.

**No process creation for `New-Item` as a separate process.** PowerShell built-in cmdlets execute within the PowerShell process space; no separate process is spawned.

## Assessment

For the specific file-creation artifact of this technique, the dataset is adequate. Sysmon Event ID 11 cleanly captures `powershell.exe` writing `wpbbin.exe` to System32, and PowerShell 4103/4104 logs record the exact cmdlet invocation. The primary detection opportunity — the appearance of `wpbbin.exe` in System32 — is directly observable. The dataset honestly reflects what a file-drop simulation produces: no firmware telemetry, no execution chain. Real-world detections for this technique rely entirely on the file artifact rather than execution telemetry.

## Detection Opportunities Present in This Data

1. **Sysmon Event ID 11**: `TargetFilename` matching `*\System32\wpbbin.exe` — creation of the UEFI persistence file artifact; any writing process is suspicious.
2. **PowerShell Event ID 4103**: `New-Item` with `name="Path"` binding containing `wpbbin.exe` — PowerShell-based file creation of the artifact.
3. **PowerShell Event ID 4104**: Script block containing `wpbbin.exe` — any script referencing this filename is worth investigating.
4. **Security 4688 / Sysmon Event ID 1**: `powershell.exe` with `wpbbin.exe` in command line — scripted creation of the firmware persistence artifact.
5. **File existence check (non-event)**: Presence of `C:\Windows\System32\wpbbin.exe` on systems without qualifying UEFI firmware (e.g., virtual machines, modern hardware without this specific BIOS feature) — anomalous file presence that can be detected via endpoint inventory queries.
