# T1112-49: Modify Registry — Event Viewer Registry Modification: Redirection Program

## Technique Context

T1112 (Modify Registry) used to redirect the Windows Event Viewer represents a persistence and execution technique that targets a tool commonly used by security practitioners themselves. By setting the `MicrosoftRedirectionProgram` value under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Event Viewer`, an attacker can specify an arbitrary executable that launches instead of (or alongside) Event Viewer when a user opens `eventvwr.exe` or `mmc.exe` with the Event Viewer snap-in.

This technique is operationally significant because it weaponizes a forensic and administrative tool. When an incident responder or system administrator attempts to open Event Viewer to investigate suspicious activity, the attacker's payload executes first. The technique has been documented in the wild and appears in several UAC bypass methods — `eventvwr.exe` runs at elevated integrity and will execute its redirection target without prompting, making this a code execution primitive as well as a persistence mechanism.

The test sets `MicrosoftRedirectionProgram` to `C:\windows\system32\notepad.exe` as a benign payload, but in a real attack this would point to the attacker's binary or an intermediate loader.

In the defended variant, this dataset produced 27 Sysmon, 14 Security, and 34 PowerShell events. The undefended capture produced 17 Sysmon, 4 Security, and 51 PowerShell events. The Security event count difference (14 vs 4) is notable — the defended run likely saw additional Security events from Defender or UAC activity. The undefended run shows only the core execution chain.

## What This Dataset Contains

The process creation chain is fully captured. Sysmon EID 1 shows `cmd.exe` (PID 1068) spawned by PowerShell (PID 1704) with:

```
"cmd.exe" /c reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Event Viewer" /v MicrosoftRedirectionProgram /t REG_EXPAND_SZ /d "C:\windows\system32\notepad.exe" /f
```

`cmd.exe` spawned `reg.exe` (PID 6572) with:

```
reg  add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Event Viewer" /v MicrosoftRedirectionProgram /t REG_EXPAND_SZ /d "C:\windows\system32\notepad.exe" /f
```

Security EID 4688 records both process creations. The `cmd.exe` creation event shows Creator Process as PowerShell and the full command with the registry path, value name, type (`REG_EXPAND_SZ` — an expandable string, appropriate for a file path that may include environment variables), and the target executable path.

Sysmon EID 10 records PowerShell accessing `whoami.exe` and `cmd.exe`. The pre-execution `whoami.exe` run is captured in both Sysmon EID 1 and Security EID 4688, confirming the test framework identity check ran under `NT AUTHORITY\SYSTEM`.

The PowerShell channel contains 51 EID 4104 events, the majority ART test framework boilerplate. One script block captures:

```
try {
    Invoke-AtomicTest T1112 -TestNumbers 49 -Confirm:$false -TimeoutSeconds 120 2>&1 | Out-String | Write-Host
} catch {
    Write-Host "ERROR: $_"
}
```

The `-TimeoutSeconds 120` parameter is unusual — it suggests the ART test framework expected this test might run longer, and the error-handling wrapper suggests the test may have been flagged for monitoring during collection.

## What This Dataset Does Not Contain

There are no Sysmon EID 12 or EID 13 events. The `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Event Viewer` path is not monitored by the sysmon-modular registry configuration used in this environment. The registry write is not directly confirmed through registry event telemetry.

The dataset does not show Event Viewer being launched after the modification. The persistence mechanism is established but no execution of the redirected program occurs within this capture window.

There is no evidence of UAC bypass behavior — in the test configuration, execution already runs under SYSTEM, so UAC bypass is not required and does not manifest.

No Application event log entries, no Event Viewer log entries, and no WMI activity appear in the dataset.

## Assessment

This dataset's detection value centers on the explicit registry path and value name visible in command-line telemetry. The `MicrosoftRedirectionProgram` value name in `Event Viewer` registry key is sufficiently specific that its appearance in a `reg add` command line is unambiguous evidence of the technique regardless of whether registry event logs capture the write.

The technique choice of `REG_EXPAND_SZ` type and a full path to a Windows executable makes the test realistic in structure — real attacks would use expandable string paths (e.g., `%APPDATA%\malware.exe`) to make the payload path less obvious in logs.

The undefended execution is clean and complete. The defended variant produced more Security events because Defender generated activity around this technique; the undefended run shows the minimal footprint of the technique itself without that noise.

## Detection Opportunities Present in This Data

**`MicrosoftRedirectionProgram` in `reg.exe` command line.** The specific value name `MicrosoftRedirectionProgram` under the Event Viewer registry path is a highly distinctive indicator. Its presence in any `reg add` command line warrants immediate investigation.

**Writes to `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Event Viewer`.** Monitoring this key for any modification — regardless of value name — covers both `MicrosoftRedirectionProgram` and any other Event Viewer hijacking variants.

**`REG_EXPAND_SZ` type in script-generated `reg add` calls.** Most automated registry modifications use `REG_DWORD` or `REG_SZ`. A `REG_EXPAND_SZ` value written by `reg.exe` from a TEMP-directory execution points to a payload path — the expandable type is specifically chosen to support environment-variable paths, which is characteristic of malware infrastructure.

**Execution chain timing relative to `whoami.exe`.** The immediate sequence of `whoami.exe` followed by `cmd.exe` targeting an Event Viewer registry key is a behavioral signature of automated script execution. The time delta between `whoami.exe` (23:51:22.053) and `cmd.exe` (23:51:24.977) is under three seconds.
