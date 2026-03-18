# T1059.001-11: PowerShell — NTFS Alternate Data Stream Execution

## Technique Context

T1059.001 PowerShell execution takes on an additional layer of stealth in this test through the use of NTFS Alternate Data Streams (ADS). ADS is a feature of the NTFS filesystem that allows multiple data streams to be attached to a single file. The primary stream is what you see when you view or open a file normally; alternate streams are invisible to basic file listings, file size reporting, and most copy operations. A file can appear to contain only a few bytes of text while its `:streamName` alternate stream holds a complete script.

This test writes a PowerShell script into an ADS of a text file in `C:\Windows\Temp\`:
```
Add-Content -Path $env:TEMP\NTFS_ADS.txt -Value 'Write-Host "Stream Data Executed"' -Stream 'streamCommand'
```

It then retrieves and executes the stream content:
```
$streamcommand = Get-Content -Path $env:TEMP\NTFS_ADS.txt -Stream 'streamCommand'
Invoke-Expression $streamcommand
```

This technique combines T1059.001 (PowerShell execution), T1564.004 (NTFS File Attributes — hiding data in alternate streams), and elements of T1027 (obfuscated payloads). The evasion value is that standard filesystem monitoring tools that watch for `.ps1` files or unusual script extensions will miss the payload entirely — it lives in a stream named `streamCommand` attached to `NTFS_ADS.txt`, a file that appears completely ordinary.

With Defender active, AMSI intercepts the `Invoke-Expression` call when the stream content is decoded and executed, blocking the payload. Without Defender, the stream content executes, and the file system events for ADS creation and content writing appear in Sysmon. This undefended dataset is specifically more valuable than the defended version for studying ADS filesystem artifacts.

## What This Dataset Contains

The dataset spans five seconds (2026-03-14T23:18:19Z to 23:18:24Z) and records 132 events across four channels: Sysmon (28), PowerShell (100), Security (3), and Application (1).

**Security EID 4688** captures two key process creation events:

1. The technique invocation:
   ```
   "powershell.exe" & {Add-Content -Path $env:TEMP\NTFS_ADS.txt -Value 'Write-Host "Stream Data Executed"' -Stream 'streamCommand'
   $streamcommand = Get-Content -Path $env:TEMP\NTFS_ADS.txt -Stream 'streamCommand'
   Invoke-Expression $streamcommand}
   ```
   This is the complete payload — stream write, stream read, and `Invoke-Expression` — all in one command block.

2. The pre-test `whoami.exe` identity check.

**Sysmon EID 15 (FileCreateStreamHash)** is the most distinctive event in this dataset. This event type is specifically designed to detect ADS creation and captures:

- `Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- `TargetFilename: C:\Windows\Temp\NTFS_ADS.txt:streamCommand`
- `Hash: SHA1=655C99A0DBBF8869F073ACCB9BE9A076027BA6FE, MD5=47AB1CE1927C2252ABA93265D66072D9, SHA256=1F4E31FD4FE1994FFE136C01C057B649CB1E838160DA89D5C4CB3B822326D0ED`
- `Contents: Write-Host "Stream Data Executed"`
- `User: NT AUTHORITY\SYSTEM`

The `TargetFilename` field uses the canonical `file.txt:streamName` ADS notation, making this unambiguous. The `Contents` field captures the literal script text stored in the stream — `Write-Host "Stream Data Executed"`. The SHA256 hash of the stream content is also recorded, enabling hash-based IOC matching against the payload.

A second EID 15 event captures the parent file (`C:\Windows\Temp\NTFS_ADS.txt`) without the stream suffix, recording the base file creation with `Hash: Unknown` (the file has minimal primary stream content).

**Sysmon EID 11 (FileCreate)** shows two events. The first is `MsMpEng.exe` creating a Defender scan temp file (`C:\Windows\Temp\01dcb408d6eaee28`), reflecting passive Defender scanning activity triggered by the file creation in Temp. The second is `powershell.exe` creating `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive` — a PowerShell profile initialization artifact for non-interactive sessions running as SYSTEM.

**Sysmon EID 7 (ImageLoad)** contributes 15 events with the standard .NET runtime and Defender DLL loads.

**Sysmon EID 10 (ProcessAccess)** shows 3 events with `GrantedAccess: 0x1FFFFF` — the standard framework-generated process access pattern.

**PowerShell EID 4104** contributes 96 events. The `Add-Content -Stream` and `Get-Content -Stream` cmdlets each generate script block entries. The `Invoke-Expression $streamcommand` call appears in EID 4104, as does the decoded stream content (`Write-Host "Stream Data Executed"`).

Compared to the defended version (38 sysmon, 12 security, 42 PowerShell), the undefended dataset shows fewer Sysmon events (28 vs. 38) — the defended version likely includes additional Defender-generated events during AMSI blocking. The EID 15 events are present in both versions since ADS creation happens before AMSI evaluation.

## What This Dataset Does Not Contain

No Sysmon EID 13 (RegistryValueSet) events are present — the technique does not touch the registry.

No network events appear — this is entirely local filesystem and in-memory execution.

The `Write-Host "Stream Data Executed"` output itself is not captured in any event — console output is not logged by Windows telemetry.

The Application channel contains one event (EID 15, Defender status update) rather than technique-related content.

## Assessment

This dataset contains the most forensically distinctive Sysmon event in the PowerShell T1059.001 group: EID 15 (FileCreateStreamHash) with the complete ADS path, file hashes, and literal content of the malicious script stored in the stream. The event is a fully self-contained indicator — it tells you exactly what was stored, where, by whom, and provides hashes for further analysis. Defenders who monitor Sysmon EID 15 will catch ADS-based payload staging at the moment of creation, regardless of subsequent execution.

The dataset is particularly useful for demonstrating the value of EID 15 monitoring and for building detection rules specific to ADS creation by PowerShell in system temp directories.

## Detection Opportunities Present in This Data

1. **Sysmon EID 15 on C:\Windows\Temp\NTFS_ADS.txt:streamCommand**: The full ADS path in `TargetFilename` is the canonical indicator. Any EID 15 event where the filename contains a `:` separator (indicating an alternate stream) is worth investigating. Streams in temp directories (`%TEMP%`, `C:\Windows\Temp`) created by PowerShell or other interpreters are particularly significant.

2. **PowerShell `Add-Content -Stream` cmdlet usage**: Both Security EID 4688 and PowerShell EID 4104 capture the `Add-Content -Stream 'streamCommand'` invocation. Detecting PowerShell cmdlets that use the `-Stream` parameter to write content is a direct indicator of ADS manipulation.

3. **PowerShell `Get-Content -Stream` followed by `Invoke-Expression`**: The read-and-execute pattern — `Get-Content -Stream X` feeding `Invoke-Expression` — is the execution step. This combination in a script block (EID 4104) indicates that content from an ADS is being executed, a high-fidelity indicator.

4. **Sysmon EID 15 Contents field containing PowerShell syntax**: The `Contents` field in the EID 15 event holds the literal stream content. When this contains PowerShell keywords, cmdlets, or `Write-Host`, `IEX`, `Invoke-`, patterns, the payload is identified before execution.

5. **File hashes from EID 15 for threat intelligence matching**: The SHA256 hash `1F4E31FD4FE1994FFE136C01C057B649CB1E838160DA89D5C4CB3B822326D0ED` identifies this specific payload. Hash-based matching against known-malicious ADS content hashes provides a scalable detection approach.

6. **MsMpEng.exe temp file creation correlated with preceding PowerShell file writes**: Sysmon EID 11 showing `MsMpEng.exe` creating a temp file shortly after PowerShell created `NTFS_ADS.txt` confirms that Defender scanned the new file. This correlation pattern can serve as a signal that a new file worth investigating was created, even in environments where Defender is passive.
