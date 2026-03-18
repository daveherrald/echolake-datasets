# T1547-1: Boot or Logon Autostart Execution — Add a Driver

## Technique Context

T1547 covers Boot or Logon Autostart Execution — mechanisms that cause adversary-controlled code to run when a system boots or a user logs on. This test exercises driver installation as a persistence vector: by registering a kernel driver through the Windows driver store, an adversary achieves code execution at boot time with kernel-level (`SYSTEM`) privileges. Kernel drivers persist across user sessions and are loaded before most defensive software.

The test uses `pnputil.exe /add-driver` to install a legitimate INF file (`C:\Windows\INF\usbstor.inf`, the USB Mass Storage driver) as a demonstration of the pathway. In a real attack, this would be replaced with a malicious INF pointing to a signed or unsigned driver binary. The use of `pnputil.exe` provides a living-off-the-land approach: `pnputil.exe` is a standard Windows utility that is present on all modern Windows installations and is legitimately used for driver management.

In the defended variant, Windows Defender (with logging) captured considerably more Security events (19 vs 5 here) due to logon/authentication auditing triggered by WMI-based invocation. Without Defender-influenced process visibility, this dataset's Security channel is leaner but still captures the core chain.

## What This Dataset Contains

The dataset spans 3 seconds (2026-03-17 17:08:06–17:08:09 UTC) on ACME-WS06 (`acme.local`), executing as `NT AUTHORITY\SYSTEM`.

**Sysmon (18 events — Event IDs 1, 7, 10, 17):**

Sysmon EID 1 (ProcessCreate, 4 events) records the attack chain:

1. `whoami.exe` — test framework context check, tagged `technique_id=T1033`
2. `cmd.exe` — tagged `technique_id=T1059.003`:
   ```
   "cmd.exe" /c pnputil.exe /add-driver "C:\Windows\INF\usbstor.inf"
   ```
3. `whoami.exe` — second test framework context check (post-execution)
4. `cmd.exe` — cleanup/teardown invocation

The `pnputil.exe` process itself does not appear in Sysmon EID 1. The sysmon-modular include configuration does not match `pnputil.exe` as a standalone process, so its presence is inferred from the parent `cmd.exe` command line. Security EID 4688 fills this gap.

Sysmon EID 7 (ImageLoad, 9 events) records .NET runtime and Defender DLLs loading into the test framework `powershell.exe`. Sysmon EID 10 (ProcessAccess, 4 events) records `powershell.exe` accessing `whoami.exe` and `cmd.exe` children. Sysmon EID 17 (PipeCreate, 1 event) records the PowerShell named pipe.

No Sysmon EID 11 (FileCreate), EID 13 (RegistrySetValue), or EID 12 (RegistryObjectAddedOrDeleted) events are present. Driver installation via `pnputil.exe` does make registry changes (adding entries under `HKLM\SYSTEM\CurrentControlSet\Enum` and `HKLM\SYSTEM\CurrentControlSet\Services`), but those paths are not captured by the sysmon-modular include rules.

**Security (5 events — Event ID 4688):**

Five process creation events:

1. `whoami.exe` created by `powershell.exe`
2. `cmd.exe` created by `powershell.exe` with command line: `"cmd.exe" /c pnputil.exe /add-driver "C:\Windows\INF\usbstor.inf"`
3. `pnputil.exe` created by `cmd.exe` with command line: `pnputil.exe /add-driver "C:\Windows\INF\usbstor.inf"`
4. `whoami.exe` (second context check)
5. `cmd.exe` (cleanup invocation: `"cmd.exe" /c`)

Security EID 4688 is the only channel that captures the `pnputil.exe` process creation with its command line. The creator process `cmd.exe` and the `NT AUTHORITY\SYSTEM` execution context are both recorded. Notably, there are no EID 4689 (process termination) or EID 4624 (logon) events in this dataset — the Security audit policy configuration in the undefended environment captures process creation but not exit events for this test.

**PowerShell (96 events — Event IDs 4103, 4104):**

ScriptBlock logging (EID 4104, 95 events) captures the outer ART test framework wrapper and the test invocation. The actual `pnputil.exe` command is passed through `cmd.exe` as a command string rather than executed directly from PowerShell, so it appears in the parent PowerShell context as a `cmd.exe` argument rather than a standalone ScriptBlock entry.

## What This Dataset Does Not Contain

- **No driver store artifacts:** `pnputil.exe /add-driver` copies the INF and associated binaries to the Windows driver store (`C:\Windows\System32\DriverStore\FileRepository\`). No Sysmon EID 11 (FileCreate) events capture this copy operation — the sysmon-modular configuration does not include the DriverStore path.
- **No registry persistence artifacts:** Driver registration creates entries in `HKLM\SYSTEM\CurrentControlSet\Services\usbstor` and related keys. No Sysmon EID 13 events capture these writes.
- **No driver load event:** The test installs the driver into the store but does not explicitly trigger it to load (the USB storage driver is already present on this system). There are no Sysmon EID 6 (DriverLoad) events.
- **No pnputil.exe in Sysmon EID 1:** The process is visible only in Security EID 4688. If the Security channel were absent or had reduced auditing, `pnputil.exe` execution would be invisible in this telemetry.

## Assessment

This dataset demonstrates a meaningful gap between Sysmon and Security telemetry: `pnputil.exe` is only visible in Security EID 4688, not in Sysmon EID 1. The dataset provides a clean record of the `cmd.exe` chain that invokes `pnputil.exe`, but the driver store and registry persistence artifacts are not represented. Analysts working solely from Sysmon would see a `cmd.exe` with a suspicious command line; those with Security audit process creation enabled would also see `pnputil.exe` with its exact arguments.

The event count parity between defended (18 Sysmon) and undefended (18 Sysmon) confirms this technique generates no defensive reactions that would add telemetry.

## Detection Opportunities Present in This Data

- **Security EID 4688:** `pnputil.exe` with `/add-driver` and a path argument, spawned by `cmd.exe` from a `powershell.exe` grandparent running as SYSTEM. `pnputil.exe` invocations from non-administrative-tooling contexts (i.e., not Windows Update or device management frameworks) are worth investigating.
- **Sysmon EID 1 / Security EID 4688:** `cmd.exe /c pnputil.exe /add-driver` as a single-shot command invocation. This pattern — wrapping `pnputil.exe` in `cmd.exe /c` rather than invoking it directly from PowerShell — is sometimes used to avoid PowerShell-based logging of the `pnputil.exe` command line.
- **Security EID 4688:** `pnputil.exe` invoked by `cmd.exe` which was itself invoked by `powershell.exe` in SYSTEM context. Driver installation from a PowerShell-via-cmd chain in SYSTEM context outside a scheduled maintenance window is anomalous.
