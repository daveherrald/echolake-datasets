# T1547.012-1: Print Processors — Print Processors - Print Processors

## Technique Context

T1547.012 (Print Processors) abuses the Windows print architecture at a deeper level than port monitors (T1547.010). Print processors are DLLs registered under `HKLM\System\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors\` that the Spooler loads when processing print jobs. Like port monitors, print processor DLLs run inside the SYSTEM-privileged `spoolsv.exe` process. The technique requires copying the DLL to the Spooler's processor directory (`C:\Windows\System32\spool\prtprocs\x64\`) and registering it in the registry. This is the more complete, two-stage variant of print-based persistence: it requires both a file drop and a registry write, and necessitates a Spooler restart to trigger DLL loading.

## What This Dataset Contains

This is the most operationally complete persistence test in this batch. The test stops the Print Spooler, copies `AtomicTest.dll` to the processor directory, registers it in the registry, and restarts the Spooler — triggering the DLL to actually load.

**File drop** — Sysmon EID 11 captures the DLL being written with the tag `technique_id=T1574.010`:
```
File created:
  Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  TargetFilename: C:\Windows\System32\spool\prtprocs\x64\AtomicTest.dll
```

**Sysmon EID 29 (File Executable Detected)** fires when the DLL is written — Sysmon's file executable detection for a new DLL dropped in the spool processor path:
```
File Executable Detected:
  RuleName: technique_id=T1059.001,technique_name=PowerShell
  Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  TargetFilename: C:\Windows\System32\spool\prtprocs\x64\AtomicTest.dll
  Hashes: SHA1=5C29EF53BAEBFA5C19CB040A916C44C9DF39A8B4,
          MD5=C20546941E0281E8E9612D9F240A75D0,
          SHA256=1986501BD94F4087957D13CFECB4B3CEDBE0ECA72678C304F08FDCD...
```

**Registry write** — Sysmon EID 13 captures the print processor registration, tagged `UACMe Dir Prep` (a sysmon-modular rule that fires on this path):
```
Registry value set:
  RuleName: UACMe Dir Prep
  Image: C:\Windows\system32\reg.exe
  TargetObject: HKLM\System\CurrentControlSet\Control\Print\Environments\
                Windows x64\Print Processors\AtomicRedTeam\Driver
  Details: AtomicTest.dll
```

**Spooler lifecycle** — Sysmon EID 1 and Security EID 4688 capture `net.exe stop spooler`, `net1 stop spooler`, `net.exe start spooler`, `net1 start spooler`, and `spoolsv.exe` restarting. The restart triggers DLL loading.

**Spooler logon** — Security events include EID 4624 (logon type 5 — service logon), EID 4627 (group membership), and EID 4672 (special privileges assigned) when spoolsv.exe starts with SYSTEM privileges.

The PowerShell EID 4104 script block is captured in full, showing the net stop/copy/reg add/net start sequence.

Sysmon event counts: 49 events across EID 1 (7), EID 7 (30), EID 10 (2), EID 11 (3), EID 13 (1), EID 17 (3), EID 29 (1). Security events: 25 events (4624, 4627, 4672, 4688 × multiple, 4689, 4703). This is the largest dataset in the batch.

## What This Dataset Does Not Contain

**Sysmon EID 7 for AtomicTest.dll loading into spoolsv.exe** — the Sysmon image load filter likely suppresses this particular DLL, or the DLL is a stub without exported print processor functions and fails to load silently. The spoolsv.exe restart is captured but no DLL load event is present for the malicious DLL specifically.

**Windows Defender** was active but did not block the DLL write or the registry registration, suggesting `AtomicTest.dll` does not match a Defender signature. Behavior monitoring did not flag the Spooler loading an unknown DLL in this instance.

**Object access auditing is disabled**, so no Security EID 4657 events for the registry write are present.

## Assessment

The test ran to completion and triggered a full DLL load cycle. This is the only dataset in this batch with Sysmon EID 29 (executable file detection), service logon events (4624/4627/4672), and a Spooler restart chain, making it the richest for detection development. The combination of file drop, registry write, service manipulation, and DLL execution in sequence provides multiple correlated detection opportunities.

## Detection Opportunities Present in This Data

- **Sysmon EID 29**: A new executable dropped in `C:\Windows\System32\spool\prtprocs\x64\` is a high-confidence, near-zero-false-positive alert. This path should never receive new files outside of legitimate printer driver installations.
- **Sysmon EID 11**: File creation in the spool processor directory by PowerShell or cmd is anomalous and should alert.
- **Sysmon EID 13**: A write to `Print\Environments\Windows x64\Print Processors\*\Driver` by `reg.exe` or PowerShell indicates print processor registration. The rule fires with `UACMe Dir Prep` tag in this dataset.
- **Security EID 4688**: `net.exe stop spooler` followed by `reg.exe` writing to a Print Environments key, followed by `net.exe start spooler` is a three-event behavioral chain with high precision.
- **Security EID 4624/4672**: A SYSTEM service logon for spoolsv.exe immediately after Spooler manipulation events provides temporal correlation confirming the Spooler restart.
- **Sequence detection**: The complete chain (PowerShell → net stop spooler → file drop to prtprocs → reg add → net start spooler) is a distinctive and detectable persistence pattern.
