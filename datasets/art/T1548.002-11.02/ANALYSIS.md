# T1548.002-11: Bypass User Account Control — UACME Method 31

## Technique Context

T1548.002 (Bypass User Account Control) covers techniques that escalate from a standard user to an administrator context without triggering the Windows UAC elevation prompt. UACME Method 31 exploits the Windows `IFileOperation` COM interface, which runs in the context of an auto-elevating process. By triggering a file copy operation through this interface, an attacker can write files to protected directories (such as `C:\Windows\System32\`) without a UAC prompt. Once a malicious DLL is planted in a trusted, privileged-load location, an auto-elevating binary loads it, resulting in elevated code execution. The test invokes `Akagi64.exe` with method number 31 as the argument.

This dataset captures the **undefended** execution on ACME-WS06 with Defender disabled. The defended variant (ACME-WS02, Defender active) produced 16 sysmon, 10 security, and 34 powershell events. The undefended dataset shows 17 sysmon, 3 security, and 96 powershell events — nearly identical sysmon counts, but lower security and higher powershell counts. The security difference (10 vs. 3) reflects the defended host's Defender-triggered additional process monitoring; in the undefended environment only the core test processes generated 4688 records.

## What This Dataset Contains

The dataset spans approximately 4 seconds on ACME-WS06 and contains 116 events across three log sources.

**Sysmon (17 events, EIDs 1, 7, 10, 11, 17):**

- **EID 1 (ProcessCreate):** Three events:
  1. `whoami.exe` (tagged `T1033`) — ART test framework pre-check
  2. `cmd.exe` (tagged `T1059.003`) with command line:
     ```
     "cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\uacme\31 Akagi64.exe"
     ```
     The method number 31 distinguishes this from other UACME tests. The path structure is identical to other UACME tests in this series.
  3. A second `whoami.exe` — ART test framework post-check.

- **EID 11 (FileCreate):** One event: `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\State\keyValueLKG.dat` (tagged `T1574.010 Services File Permissions Weakness`). This is an ambient Delivery Optimization service state file write, unrelated to the UACME bypass. The timing coincidence within the test window is incidental.

- **EID 10 (ProcessAccess):** Three events tagged `T1055.001` — test framework PowerShell acquiring full-access handles to `whoami.exe` and `cmd.exe`.

- **EID 17 (PipeCreate):** One named pipe creation event.

- **EID 7 (ImageLoad):** Nine DLL load events for PowerShell initialization.

**No Sysmon EID 1 for Akagi64.exe.** As with Method 23 (T1548.002-10), the sysmon-modular include-mode ProcessCreate configuration does not capture UACME binary process creation. The `cmd.exe` that invoked `Akagi64.exe` is captured; `Akagi64.exe` itself is not.

**Security (3 events, all EID 4688):** Process creation records for `whoami.exe` (once) and `cmd.exe`:

```
NewProcessName: C:\Windows\System32\cmd.exe
CommandLine: "cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\uacme\31 Akagi64.exe"
```

No Security EID 4688 for `Akagi64.exe`, no process creation records for any elevated child processes spawned by the bypass.

**PowerShell (96 events, EIDs 4104 × 95, 4103 × 1):** Entirely ART test framework boilerplate. The technique was invoked through `cmd.exe`; the PowerShell channel provides no attack-specific content.

## What This Dataset Does Not Contain

**No Akagi64.exe process creation.** In the undefended environment, `Akagi64.exe` ran without Defender blocking it. However, neither Sysmon EID 1 nor Security EID 4688 captured its process creation. This is a monitoring gap in the logging configuration, not a Defender action.

**No IFileOperation artifacts.** Method 31's file copy operation to a protected directory would appear as Sysmon EID 11 (FileCreate) in `C:\Windows\System32\` or similar. No such event is present. Either the copy failed (method-specific failure or path condition not met), or the file create event fell outside the captured event sample.

**No elevated process chain.** No auto-elevating process spawning an elevated child is visible. The bypass execution chain is either not present or not captured.

**No registry events.** Method 31 may involve registry staging as part of the bypass; no EID 13 events related to the bypass are present.

## Comparison with Other UACME Tests

This dataset is structurally the same as T1548.002-10 (Method 23) and other UACME tests in this series. All show:
- `cmd.exe` invocation captured in Sysmon EID 1 and Security EID 4688
- Akagi64.exe process creation absent from both Sysmon and Security
- No bypass execution chain visible
- Entirely test framework-boilerplate PowerShell events

The primary differentiator between UACME method datasets is the method number in the `cmd.exe` command line. The datasets collectively establish that the configured logging does not capture UACME binary process creation in either defended or undefended environments. The most distinctive element of each method dataset is the `cmd.exe` command line argument (the method number).

The one distinguishing artifact in this dataset versus Method 23 is the Sysmon EID 11 event for the Delivery Optimization state file — ambient system activity that happens to appear in this window but not in Method 23's window. This is coincidental noise, not technique-specific.

## Assessment

As with Method 23, the `cmd.exe` invocation record is the primary forensic artifact. In the undefended environment, `Akagi64.exe` ran without interference from Defender, but its execution chain is not captured in the configured logging. The dataset provides evidence that the bypass was attempted but not evidence of whether it succeeded.

The fact that Akagi64.exe ran in the undefended environment without generating process creation records — while Defender actively blocked it in the defended environment (based on the defended dataset's absence of an elevated process chain) — means detection in a real-world undefended environment would rely almost entirely on the `cmd.exe` command line containing the UACME binary path.

## Detection Opportunities Present in This Data

- **Security EID 4688 and Sysmon EID 1:** `cmd.exe` invocation with `Akagi64.exe` in the command line. The filename is well-known and should be treated as an unambiguous alert trigger. In real-world attacks the binary may be renamed, but the ExternalPayloads path or UACME-derived naming patterns are still detectable.

- **Sysmon EID 1 rule gap:** Adding explicit include patterns for `Akagi64.exe`, `Akagi.exe`, and common UACME variant names to the sysmon ProcessCreate configuration would close the monitoring gap present in this dataset.

- **Sysmon EID 11:** File creation events in `C:\Windows\System32\`, `C:\Windows\SysWOW64\`, or other auto-elevating binary directories by processes that are not Windows Update, installer services, or trusted management tools. Method 31's `IFileOperation` write would appear here on successful execution.

- **Process tree analysis:** Any auto-elevating Windows binary (`wusa.exe`, `eventvwr.exe`, `mmc.exe`, etc.) spawning unexpected child processes after an anomalous parent chain is a UAC bypass indicator.

- **Token elevation without consent:** Security EID 4688 processes with `TokenElevationType: %%1937` (elevated) that did not originate from `consent.exe` represent potential UAC bypass events.

- **Correlation with Method 23 (T1548.002-10):** If both methods are attempted in the same session, analysts will see multiple `cmd.exe` invocations with sequentially numbered UACME method arguments. The method number in the command line is a distinguishing field for attribution.
