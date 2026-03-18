# T1055.012-1: Process Hollowing — Process Hollowing using PowerShell

## Technique Context

T1055.012 Process Hollowing is an advanced process injection technique where an attacker creates a legitimate process in a suspended state, unmaps its original executable from memory, replaces it with malicious code, and then resumes execution. The result is a legitimate process name and path in the process list, but with the process executing attacker-controlled code. The Windows kernel's process structures still point to the original image path, so tools that enumerate processes by looking at the executable path will see `notepad.exe` rather than whatever code is actually running.

The canonical API sequence for process hollowing is: `CreateProcess` with `CREATE_SUSPENDED`, `NtUnmapViewOfSection` to remove the original image, `VirtualAllocEx` to allocate memory for the payload, `WriteProcessMemory` to write the payload, `SetThreadContext` to redirect the entry point, and `ResumeThread`. This sequence is well-documented and actively monitored by mature EDR products. However, PowerShell-based implementations can evade simpler detection approaches that rely on monitoring unmanaged API calls directly, since the calls may route through .NET runtime abstractions.

The ART test uses `Start-Hollow.ps1`, a PowerShell implementation loaded from `C:\AtomicRedTeam\atomics\T1055.012\src\Start-Hollow.ps1`. The attack hollows `notepad.exe` (the "sponsor" — the legitimate host process) and injects `cmd.exe` (the "hollow" — the payload). Parent process spoofing is also applied via `-ParentPID $ppid` using the `explorer.exe` PID, which makes the hollowed process appear to be a child of Explorer in the process tree.

## What This Dataset Contains

The PowerShell implementation runs successfully with Defender disabled. The dataset captures multiple telemetry layers.

**Security EID 4688 — process creation (4 events):** The child PowerShell command fully exposes the attack:

```
"powershell.exe" & {. "C:\AtomicRedTeam\atomics\T1055.012\src\Start-Hollow.ps1"
$ppid=Get-Process explorer | select -expand id
Start-Hollow -Sponsor "C:\Windows\System32\notepad.exe" -Hollow "C:\Windows\System32\cmd.exe" -ParentPID $ppid -Verbose}
```

The script dot-sourced into the PowerShell session, the sponsor path (`notepad.exe`), the hollow payload (`cmd.exe`), and the parent PID spoofing are all visible. A cleanup command `Stop-Process -Name "notepad" -ErrorAction Ignore` follows.

**Sysmon EID 1 — process create (4 events):** `whoami.exe` (tagged `T1033`) and the child PowerShell executing the hollow command (tagged `T1059.001,technique_name=PowerShell`). `notepad.exe` does not appear in Sysmon EID 1 — a significant gap, since seeing `notepad.exe` created from a PowerShell parent in SYSTEM context would be a strong indicator. The include-mode filter does not match notepad.

**Sysmon EID 10 — process access (4 events):** PowerShell (PID 3168) accessing `whoami.exe` (PID 5164) and a child PowerShell (PID 900) with `GrantedAccess: 0x1fffff`. ART test framework events. Notably absent are process access events from the PowerShell hollow script to `notepad.exe` — these would represent the actual hollowing operations (`OpenProcess`, `NtUnmapViewOfSection`, `WriteProcessMemory`) and would be the primary behavioral injection indicators.

**Sysmon EID 7 — image load (22 events):** .NET CLR DLLs and Defender components in PowerShell processes. No image loads in the notepad process are captured.

**Sysmon EID 2 — file creation time changed (1 event):** `MsMpEng.exe` (Windows Defender engine) modifies the creation timestamp of `C:\AtomicRedTeam\atomics\T1055.004\bin\T1055.exe` (a different test's binary). This reflects Defender's background scanning activity. Sysmon tags this as `technique_id=T1099,technique_name=Timestomp` — Defender touching binaries during scanning creates timestomp artifacts.

**Sysmon EID 11 — file create (2 events):** Includes `C:\Windows\Temp\01dcb4089268cbe5`, a temporary file created by `MsMpEng.exe`, tagged `technique_id=T1574.010,technique_name=Services File Permissions Weakness`. This is a Defender scanning artifact.

**Sysmon EID 17 — named pipe create (3 events):** PowerShell host pipes.

**Application EID 15 (1 event):** Defender status reconciliation.

**PowerShell EID 4104 (113 events):** The highest PowerShell event count in this batch. The additional events likely correspond to the `Start-Hollow.ps1` script being dot-sourced and its internal functions compiling into script blocks. However, the actual hollow execution code (`Start-Hollow` function internals) does not appear in the samples — it may be in the non-sampled events.

**Comparison to defended dataset:** The defended version recorded 46 sysmon, 10 security, and 53 powershell events. The undefended dataset: 36 sysmon, 4 security, 113 powershell events. More PowerShell events in the undefended run (script loaded and executed further), fewer Sysmon events (Defender's scanning artifacts absent). The 113 PowerShell events versus 53 in the defended run strongly suggests the `Start-Hollow.ps1` script body was logged by script block logging in the undefended run (the defender-blocked run stopped earlier). This additional script content may be in the non-sampled events.

## What This Dataset Does Not Contain

- No Sysmon EID 10 from the PowerShell hollow script to `notepad.exe`. The `OpenProcess` call for the target process is not captured.
- No Sysmon EID 1 for `notepad.exe` being created in suspended state. The hollowing target creation is invisible in Sysmon.
- No Sysmon EID 8 (CreateRemoteThread). Process hollowing typically uses `SetThreadContext` + `ResumeThread` rather than creating a new remote thread, so EID 8 absence is expected for this technique variant.
- No image load events showing `cmd.exe`'s PE loading into the hollowed notepad's address space.
- The `Start-Hollow.ps1` function implementation does not appear in the sampled PowerShell script blocks (though it may exist in the non-sampled events given the 113 total).

## Assessment

This dataset provides good command-line visibility into the process hollowing invocation — the sponsor, hollow, and parent PID spoofing parameters are all exposed. However, the injection mechanics themselves (process suspension, memory unmapping, payload writing, context setting) are not captured by the standard Sysmon configuration. Process hollowing is specifically resistant to CreateRemoteThread-based detection, and this dataset confirms that absence.

The elevated PowerShell event count (113 vs 53 in the defended run) suggests that the undefended execution ran further and logged more script content. Investigators with access to the full (non-sampled) script block events from this dataset may find the `Start-Hollow.ps1` function implementation, which would be valuable for understanding the technique's PowerShell-native API usage patterns.

The MsMpEng-generated timestomp and temp file artifacts are interesting background noise — they demonstrate that even when Defender is disabled, its engine still performs some file activity (scanning artifacts), which can create misleading T1099 (Timestomp) and T1574.010 (Services File Permissions Weakness) signals from the Sysmon rule tags.

## Detection Opportunities Present in This Data

1. Security EID 4688 and Sysmon EID 1 `CommandLine` containing `Start-Hollow.ps1` and `Start-Hollow -Sponsor ... -Hollow ... -ParentPID` — the script path and function name are direct, unique indicators.

2. The specific combination of `notepad.exe` as sponsor and `cmd.exe` as the hollow payload in `-Sponsor "C:\Windows\System32\notepad.exe" -Hollow "C:\Windows\System32\cmd.exe"` — running `cmd.exe` inside a hollowed `notepad.exe` is a classic demonstration pattern.

3. `-ParentPID $ppid` with the `explorer.exe` PID is parent process ID spoofing — in environments that track parent-child process relationships, a `notepad.exe` process appearing as a child of `explorer.exe` but having been created from a SYSTEM PowerShell context would be anomalous.

4. PowerShell dot-sourcing (`". "C:\AtomicRedTeam\atomics\T1055.012\src\Start-Hollow.ps1""`) a file from an atomics directory establishes a baseline for detection development. In production, dot-sourcing scripts from temp directories or unusual paths by SYSTEM-level PowerShell warrants investigation.

5. Sysmon EID 2 (`technique_id=T1099,technique_name=Timestomp`) events generated by `MsMpEng.exe` are false-positive indicators of timestomping — detection rules matching EID 2 should exclude `MsMpEng.exe` as the source image to avoid Defender scanning activity triggering T1099 alerts.

6. Sysmon EID 11 file creation in `C:\Windows\Temp\` by `MsMpEng.exe` with the `T1574.010` rule tag is similarly a false positive from Defender scanning. The rule tag may be overly broad in matching temp file creation by any process.

7. In environments with PowerShell script block logging capturing the full non-sampled output, the `Start-Hollow.ps1` function body (including its .NET P/Invoke calls for `NtUnmapViewOfSection`, `WriteProcessMemory`, etc.) would provide valuable ground-truth API signatures for behavioral detection development.
