# T1547-2: Boot or Logon Autostart Execution — Driver Installation Using pnputil.exe

## Technique Context

T1547 covers Boot or Logon Autostart Execution. This test exercises `pnputil.exe` as a driver installation mechanism for persistence, using the combined install-and-add flags `-i -a` rather than just `/add-driver` as in T1547-1. The `-i -a` syntax (`pnputil -i -a <inf>`) installs the driver package into the driver store and attempts immediate installation, whereas `/add-driver` only stages it. This distinction matters for detection: `-i -a` causes `pnputil.exe` to load the driver immediately if hardware is present, which would generate a Sysmon EID 6 (DriverLoad) event; `/add-driver` alone may not.

The test target is `C:\Windows\INF\acpipmi.inf` (the ACPI Platform Management Interface driver), a legitimate Windows component used as a stand-in for a malicious driver payload. In a real attack, the INF would reference a malicious `.sys` file.

Unlike T1547-1 (which used `cmd.exe /c pnputil.exe`), this test invokes `pnputil.exe` directly from PowerShell without an intermediate `cmd.exe` wrapper, producing a different process lineage.

The undefended dataset (29 Sysmon events) is smaller than the defended variant (37 Sysmon events). The difference reflects additional EID 7 DLL loads in the defended variant from Defender scanning the pnputil execution.

## What This Dataset Contains

The dataset spans 3 seconds (2026-03-17 17:08:22–17:08:25 UTC) on ACME-WS06 (`acme.local`), executing as `NT AUTHORITY\SYSTEM`.

**Sysmon (29 events — Event IDs 1, 7, 10, 11, 17):**

Sysmon EID 1 (ProcessCreate, 4 events) records:

1. `whoami.exe` — test framework context check, tagged `technique_id=T1033`
2. `powershell.exe` — tagged `technique_id=T1059.001` with command line:
   ```
   "powershell.exe" & {pnputil.exe -i -a C:\Windows\INF\acpipmi.inf}
   ```
3. `whoami.exe` — second context check
4. `powershell.exe` with empty body (`& {}`) — cleanup/teardown test framework

The `pnputil.exe` process is not captured in Sysmon EID 1 — the sysmon-modular include filter did not match it. As with T1547-1, Security EID 4688 is required to confirm the actual `pnputil.exe` execution.

Sysmon EID 7 (ImageLoad, 17 events) records DLL loads into the two PowerShell instances: .NET runtime, Defender, and URL moniker DLLs. Sysmon EID 10 (ProcessAccess, 5 events) records `powershell.exe` accessing `whoami.exe` and `pnputil.exe`. Sysmon EID 11 (FileCreate, 1 event) records the PowerShell startup profile data file. Sysmon EID 17 (PipeCreate, 2 events) records PowerShell named pipes.

**Security (5 events — Event ID 4688):**

Five process creation events:

1. `whoami.exe` created by `powershell.exe`
2. `powershell.exe` created by its parent — full command line: `"powershell.exe" & {pnputil.exe -i -a C:\Windows\INF\acpipmi.inf}`
3. `pnputil.exe` created by `powershell.exe` — command line: `"C:\Windows\system32\pnputil.exe" -i -a C:\Windows\INF\acpipmi.inf`
4. `whoami.exe` (second context check)
5. `powershell.exe` with empty body

Security EID 4688 confirms that `pnputil.exe` was invoked directly by `powershell.exe` (not via `cmd.exe`), with the `-i -a` flags and `acpipmi.inf` as the target. The `NT AUTHORITY\SYSTEM` context is recorded. There are no EID 4689 exit events in this dataset.

**PowerShell (99 events — Event IDs 4103, 4104):**

ScriptBlock logging captures the full test payload `pnputil.exe -i -a C:\Windows\INF\acpipmi.inf` within the PowerShell block, providing a second record of the command independent of Security EID 4688.

## What This Dataset Does Not Contain

- **No pnputil.exe in Sysmon EID 1:** As in T1547-1, `pnputil.exe` is visible only via Security EID 4688 and is not captured by the sysmon-modular include rules for process creation.
- **No Sysmon EID 6 (DriverLoad):** Despite the `-i` (install immediately) flag, no driver load event is recorded. The `acpipmi.inf` driver may already be present on the system, preventing a new load event, or the hardware enumeration may not trigger an immediate load in this context.
- **No driver store file artifacts:** Sysmon EID 11 does not capture the INF or binary copy to the driver store.
- **No registry persistence artifacts:** No Sysmon EID 13 events capture the service or device registry entries created by the installation.

## Assessment

This dataset shows the same structural pattern as T1547-1 but with the key difference that `pnputil.exe` is invoked directly from PowerShell rather than through `cmd.exe /c`. This makes the PowerShell command line itself (`& {pnputil.exe -i -a ...}`) the primary indicator in both Sysmon EID 1 and PowerShell EID 4104. Security EID 4688 again provides the only direct `pnputil.exe` process creation record.

The T1547-1 and T1547-2 datasets together illustrate two common invocation patterns for `pnputil.exe` and the different process trees each creates — useful for building parent-process-aware detection logic.

## Detection Opportunities Present in This Data

- **Sysmon EID 1 / Security EID 4688:** `powershell.exe` executing `pnputil.exe -i -a` directly (without a `cmd.exe` intermediary). The `-i -a` flag combination, especially with a non-standard INF path, is specifically the install-and-load mode.
- **Security EID 4688:** `pnputil.exe` with `-i -a` and an INF path, created directly by `powershell.exe` in SYSTEM context. Compared to T1547-1's `cmd.exe /c pnputil.exe /add-driver` pattern, this variant's direct PowerShell invocation is a different process lineage that requires a different parent-process filter.
- **PowerShell EID 4104:** `pnputil.exe -i -a` as a bare command within a PowerShell ScriptBlock. The combination of a driver management utility invoked directly from a PowerShell script block (rather than via a cmdlet) is uncommon outside automated IT management frameworks.
- **Sysmon EID 10:** `powershell.exe` with `GrantedAccess: 0x1FFFFF` on `pnputil.exe`. While this is normal ART test framework behavior, in isolation it represents unusual process access patterns between a scripting host and a driver utility.
