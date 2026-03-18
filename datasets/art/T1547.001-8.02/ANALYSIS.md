# T1547.001-8: Registry Run Keys / Startup Folder — Add Persistence via Recycle Bin

## Technique Context

T1547.001 (Registry Run Keys / Startup Folder) includes a lesser-known sub-variant that abuses the Windows Recycle Bin COM object registration. The Recycle Bin has a CLSID (`{645FF040-5081-101B-9F08-00AA002F954E}`) registered in `HKCR` (HKEY_CLASSES_ROOT) with a shell open command handler. By overwriting the default value of `HKCR\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell\open\command\(Default)`, an attacker causes arbitrary code to execute whenever a user opens the Recycle Bin in Windows Explorer. This is classified under T1547.001 because it achieves automatic execution tied to a user shell interaction, using the registry COM handler mechanism. It requires SYSTEM or administrator privileges to write to HKCR system-wide, though per-user overrides in HKCU are also possible.

This dataset captures the **undefended** execution of ART test T1547.001-8 on ACME-WS06 with Defender disabled. The defended variant (ACME-WS02, Defender active) shows nearly identical event structure: sysmon 19 vs. 38, security 4 vs. 12, powershell 96 vs. 34. The higher defended sysmon count reflects Defender's process interrogation overhead, not additional technique telemetry. Defender does not block the `reg.exe` registry write for this COM handler path.

## What This Dataset Contains

The dataset spans approximately 6 seconds on ACME-WS06 and contains 119 events across three log sources.

**The attack action** is entirely captured through `reg.exe` invoked via `cmd.exe`. The ART test framework used the command-line registry tool rather than PowerShell's registry provider for this test, which is why the PowerShell channel is dominated by test framework boilerplate rather than attack-specific content.

**Sysmon (19 events, EIDs 1, 7, 10, 11, 13, 17):**

- **EID 1 (ProcessCreate):** Four process creation events. `whoami.exe` (tagged `T1033`) appears twice — the ART test framework pre- and post-check. `cmd.exe` is captured with the full command line:
  ```
  "cmd.exe" /c reg ADD "HKCR\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell\open\command" /ve /d "calc.exe" /f
  ```
  `reg.exe` is captured with the final parsed command:
  ```
  reg  ADD "HKCR\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell\open\command" /ve /d "calc.exe" /f
  ```

- **EID 13 (RegistrySetValue):** One event capturing the registry write. The `RuleName` field is `-` (no named rule match in sysmon-modular), confirming the config does not have a specific include rule targeting this CLSID path. The event nonetheless captures the key path and written value (`calc.exe`). This is the primary persistence indicator.

- **EID 11 (FileCreate):** One file create for `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive` — a PowerShell profile artifact from the test framework startup, not related to the attack.

- **EID 10 (ProcessAccess):** Three events tagged `T1055.001` — the ART test framework PowerShell process acquiring handles to its child processes.

- **EID 17 (PipeCreate):** One named pipe for the PowerShell host runtime.

- **EID 7 (ImageLoad):** Nine DLL load events for PowerShell initialization, tagged with `T1055`, `T1059.001`, and `T1574.002` rules.

**Security (4 events, all EID 4688):** Process creation records for `whoami.exe` (twice), `cmd.exe`, and `reg.exe`. The 4688 records include full command lines. The `cmd.exe` and `reg.exe` entries independently document the HKCR modification:

```
NewProcessName: C:\Windows\System32\cmd.exe
CommandLine: "cmd.exe" /c reg ADD "HKCR\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell\open\command" /ve /d "calc.exe" /f
```

```
NewProcessName: C:\Windows\System32\reg.exe
CommandLine: reg  ADD "HKCR\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell\open\command" /ve /d "calc.exe" /f
```

**PowerShell (96 events, EIDs 4104 × 95, 4103 × 1):** Almost entirely ART test framework boilerplate. No meaningful attack-specific PowerShell content — the test framework executed this test by spawning `cmd.exe` rather than using native PowerShell registry cmdlets.

## What This Dataset Does Not Contain

**No Recycle Bin payload execution.** The modified COM handler runs when a user opens the Recycle Bin in Explorer. No such interaction occurred during the test window; there is no process-create event for `calc.exe` launched from this handler.

**No cleanup artifacts.** The ART cleanup action (restoring the original `(Default)` value) is present in the defended dataset's Security EID 4688 records but the undefended dataset's shorter time window may not include it. The persistence modification remains in place at the end of the captured window.

**No named T1547.001 rule in Sysmon EID 13.** The sysmon-modular config does not have a specific include rule targeting this CLSID. Detection of this registry path requires either a broad HKCR monitoring rule or explicit enumeration of the Recycle Bin CLSID.

**No Sysmon EID 12 (RegistryCreateKey).** The CLSID key itself pre-exists; only the value was modified. Sysmon captures the value write (EID 13) but not a key creation.

## Assessment

The essential forensic record for this technique is the Sysmon EID 13 capturing `HKCR\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell\open\command` being set to `calc.exe`. This single event, combined with the Security EID 4688 records showing `reg.exe` with the CLSID path in its command line, tells the complete story of the persistence installation.

What makes this variant notable is the HKCR targeting rather than the more commonly monitored Run key paths. Security teams often focus registry monitoring on `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` and similar paths; HKCR COM handler modifications receive less attention despite being a viable persistence vector.

The use of `reg.exe` via `cmd.exe` (rather than PowerShell) is also worth noting for analyst calibration: this is the telemetry profile you will see when the same operation is performed by non-PowerShell tooling or scripts. The PowerShell log provides no useful attack content in this test; the action evidence is entirely in Sysmon and Security process creation events.

## Detection Opportunities Present in This Data

- **Sysmon EID 13:** Any write to `HKCR\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell\open\command` or its subkeys. The Recycle Bin CLSID is fixed and well-known; writes to its shell handler are highly anomalous outside of Windows setup or shell extension installation.

- **Security EID 4688:** `reg.exe` execution with command-line arguments referencing the Recycle Bin CLSID (`645FF040-5081-101B-9F08-00AA002F954E`). The GUID string in a `reg.exe` command line is a specific, searchable pattern.

- **Sysmon EID 1:** `cmd.exe` spawned from PowerShell (or any unusual parent) with `reg.exe` in the command string and the Recycle Bin CLSID. The parent-child chain of `powershell.exe → cmd.exe → reg.exe` is unusual for routine system administration.

- **Correlation:** Pairing EID 1 (`cmd.exe` / `reg.exe` with CLSID) and EID 13 (registry value set at same path) via timestamp or process GUID provides high-confidence confirmation of the technique.
