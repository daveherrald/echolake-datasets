# T1564.003-1: Hidden Window — Hidden Window

## Technique Context

T1564.003 (Hidden Window) is a defense-evasion sub-technique in which an adversary launches a process with a hidden or minimized window to avoid drawing attention from an interactive user. On Windows, the most common implementation is PowerShell's `-WindowStyle hidden` flag, which sets the window state to `SW_HIDE` at process creation. The technique is often used as a wrapper around follow-on payload execution: the attacker spawns a hidden shell that in turn runs their next-stage tool without a visible console window appearing on the desktop.

## What This Dataset Contains

The test invokes `Start-Process powershell.exe -WindowStyle hidden calc.exe`, a canonical ART demonstration of the technique using the Calculator as a benign stand-in for a payload.

**Security log (4688) — process creation chain:**
- `powershell.exe` with command line `"powershell.exe" & {Start-Process powershell.exe -WindowStyle hidden calc.exe}` spawns a child `powershell.exe`
- That child PowerShell spawns `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" calc.exe` (the hidden intermediate)
- The hidden PowerShell spawns `"C:\Windows\system32\calc.exe"` — the payload process

All three layers record 4688 (process creation) and 4689 (process termination) with exit status `0x0`, confirming successful execution to completion.

**Sysmon EID 1** captures the same chain with full process GUIDs, hashes, and parent command lines, making it possible to reconstruct the execution tree without gaps. The hidden intermediate is tagged with `RuleName: technique_id=T1059.001` by the sysmon-modular configuration.

**PowerShell script block logging (4104)** records the exact script block `{Start-Process powershell.exe -WindowStyle hidden calc.exe}` and the outer invocation that wraps it, providing a third independent copy of the technique command.

**4703 (Token Right Adjusted)** records privilege enablement for the SYSTEM-context PowerShell, including `SeAssignPrimaryTokenPrivilege` and related process-launch privileges.

## What This Dataset Does Not Contain (and Why)

There is no Sysmon EID 1 event for `calc.exe` itself. The sysmon-modular configuration uses include-mode ProcessCreate rules targeting known-suspicious patterns (LOLBins, scripting engines, accessibility tools, etc.). `calc.exe` launched by PowerShell is not in those include rules, so it falls through. Security 4688 fills this gap with the `calc.exe` process creation record.

No network activity is present. The test payload (calc.exe) makes no network connections, and `-WindowStyle hidden` alone produces no network telemetry.

No file write events for the payload are generated because `calc.exe` is a pre-existing system binary, not a dropped file.

## Assessment

The technique executed successfully. The three-level PowerShell → hidden-PowerShell → calc.exe chain is fully documented across both the Security log and Sysmon. The `-WindowStyle hidden` flag is captured verbatim in three separate event sources: the 4688 command line, the Sysmon EID 1 command line, and the PowerShell 4104 script block. An analyst has everything needed to detect, pivot, and reconstruct the kill chain.

## Detection Opportunities Present in This Data

- **4688 command line contains `-WindowStyle hidden`**: the string `hidden` in a PowerShell command line argument is a reliable, low-false-positive indicator for this technique.
- **Parent-child PowerShell spawning PowerShell**: `powershell.exe` → `powershell.exe` with a script block argument is unusual in baseline enterprise environments and warrants investigation regardless of window style.
- **4104 script block logging**: the exact `Start-Process ... -WindowStyle hidden` call is recorded verbatim, enabling keyword-based alerting that is robust to minor command-line obfuscation.
- **Sysmon EID 1 with `technique_id=T1059.001` RuleName**: sysmon-modular tags the hidden child PowerShell, providing a pre-enriched detection field.
- **4703 privilege adjustment for SYSTEM-context PowerShell**: a high-privilege PowerShell session enabling process-launch privileges is consistent with adversary automation and can serve as a supporting indicator.
