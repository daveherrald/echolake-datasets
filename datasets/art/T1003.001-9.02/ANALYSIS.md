# T1003.001-9: LSASS Memory — Create Mini Dump of LSASS.exe using ProcDump

## Technique Context

T1003.001 (LSASS Memory) involves dumping the memory of the Local Security Authority Subsystem Service to extract credential material including NTLM hashes, Kerberos tickets, and plaintext passwords for recently authenticated users. ProcDump is a Sysinternals utility that Microsoft provides for legitimate diagnostic purposes — it creates process memory dumps for crash analysis. Attackers and red teams favor it precisely because it is a signed Microsoft binary, it does not trigger most application control policies by hash, and it produces output that is functionally identical to what a custom dump tool would create.

Using a trusted system binary to accomplish an attack goal is a classic living-off-the-land approach. ProcDump accepts a process ID or name as a target, making LSASS dumps a one-liner: `procdump.exe -accepteula -ma lsass.exe output.dmp`. The `-ma` flag requests a full memory dump (MiniDump with all memory), which contains the credential material. Detection approaches focus on ProcDump's Sysmon EID 10 access patterns against LSASS, the creation of dump files by ProcDump, and command line arguments containing "lsass".

This dataset captures what ProcDump's execution looks like against an undefended host. The defended version captured a blocked attempt — the key difference here is whether the dump file actually lands on disk and whether the LSASS process access events complete.

## What This Dataset Contains

This dataset was collected from ACME-WS06 (Windows 11 Enterprise Evaluation, `acme.local` domain) with Windows Defender disabled. The test ran as `NT AUTHORITY\SYSTEM`.

**Sysmon channel (52 events: 42x EID 11, 4x EID 1, 4x EID 10, 1x EID 17, 1x EID 7):** The EID 1 process creation events show the execution chain clearly. `powershell.exe` (PID 5200) spawns `whoami.exe` (PID 4648) via EID 1 at 22:44:44 UTC — this is the ART test framework pre-check. A second EID 1 shows `cmd.exe` (PID 1320) created with the command `"cmd.exe" /c del "C:\Windows\Temp\lsass_dump.dmp" >nul 2> nul` — this is the cleanup step, and it directly reveals the dump file path: `C:\Windows\Temp\lsass_dump.dmp`. This confirms the dump was created during execution. EID 10 events show `powershell.exe` (PID 5200) opening both `whoami.exe` and `cmd.exe` with `GrantedAccess: 0x1FFFFF` — these reflect the ART test framework spawning child processes. The EID 17 pipe creation `\PSHost.134180018808839598.5200.DefaultAppDomain.powershell` identifies the driving PowerShell session.

**Security channel (11 events: 7x EID 5379, 4x EID 4688):** EID 4688 events confirm the process chain: `powershell.exe` (PID 0x1450) spawns `whoami.exe` (0x1228), then `cmd.exe` (0x8a8) with command line referencing `C:\AtomicRedTeam\at...` (truncated, the ProcDump invocation path), then another `whoami.exe` (0x848), then `cmd.exe` (0x528) with a command line beginning `"cmd.exe" /c del "C:\Windows\Temp\lsass_d` — again confirming the dump file. EID 5379 records seven credential manager enumeration events by ACME-WS06$ running as SYSTEM, which is routine system behavior in this environment.

**PowerShell channel (104 events: 102x EID 4104, 2x EID 4103):** The 102 script block events include the ART module load (`Import-Module 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1' -Force`) and standard PowerShell runtime stubs. EID 4103 (module logging) appears twice, suggesting the ART module executed functions that triggered module-level event logging in addition to script block logging.

**Compared to the defended dataset (sysmon: 25, security: 9, powershell: 42):** The undefended run produced 52 Sysmon events vs. 25 defended — double the volume. More importantly, the cleanup command (the `del lsass_dump.dmp` invocation visible in EID 1 and EID 4688) only appears in the undefended dataset. In the defended run, ProcDump was blocked before creating the dump, so no cleanup was needed. The presence of the cleanup command is a direct indicator that the dump completed successfully.

## What This Dataset Does Not Contain

The 20-event Sysmon sample is dominated by EID 11 file creation events from Windows Update and AppX installation activity happening concurrently with the test. The specific Sysmon EID 1 for ProcDump itself (the `procdump.exe -ma lsass.exe` invocation) and the EID 10 event showing ProcDump accessing LSASS directly are in the full dataset but not in the 20-event preview window. The dump file creation event (EID 11 for `C:\Windows\Temp\lsass_dump.dmp`) is similarly in the full dataset. There are no network events, no registry modifications, and no persistence mechanisms — this is a pure dump-and-exfiltrate scenario without lateral movement artifacts.

## Assessment

This is a high-value undefended credential dumping dataset. The cleanup command's presence in both Security EID 4688 and Sysmon EID 1 provides unambiguous confirmation that `C:\Windows\Temp\lsass_dump.dmp` was created — something absent in the defended version. The dataset is useful for validating detection rules against ProcDump's exact execution pattern, testing whether process creation monitoring catches the dump invocation, and understanding the complete artifact set (process chain, file creation, cleanup) left by this technique when Defender offers no resistance.

## Detection Opportunities Present in This Data

1. **EID 4688 / Sysmon EID 1 — ProcDump command line:** `procdump.exe` appearing in a process creation event with `-ma` and `lsass` in the command line is a tier-1 detection. The cleanup command `del "C:\Windows\Temp\lsass_dump.dmp"` in a `cmd.exe` child of PowerShell reveals both the tool path and the dump location.

2. **EID 10 (Sysmon Process Access) — ProcDump targeting LSASS:** ProcDump's process access pattern against `lsass.exe` with `GrantedAccess: 0x1FFFFF` (or `0x1010`) is a well-documented detection signal. The `CallTrace` field shows the specific DLL call path used to open the handle.

3. **EID 11 (Sysmon File Creation) — dump file in temp directory:** A `.dmp` file created in `C:\Windows\Temp\` by a non-debugger process, especially one named `lsass_dump.dmp`, is a near-certain indicator of a completed credential dump attempt.

4. **EID 4688 (Security Process Creation) — cleanup chain:** Detecting `cmd.exe /c del [path]\lsass*.dmp` as a child of `powershell.exe` running as SYSTEM is a post-exploitation cleanup pattern that signals the dump already completed. The cleanup is often easier to detect than the dump itself.

5. **EID 4103 (PowerShell Module Logging):** The presence of EID 4103 alongside EID 4104 indicates the ART module invoked exported functions (not just inline code). Correlating module logging with subsequent LSASS-related process activity chains the PowerShell session to the dump attempt.

6. **Sysmon EID 17 — PowerShell pipe creation correlated with LSASS access:** Cross-correlating the `\PSHost.*` named pipe creation with subsequent EID 10 events from the same PID provides a session anchor for the entire credential dump chain.
