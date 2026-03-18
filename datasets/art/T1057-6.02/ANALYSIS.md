# T1057-6: Process Discovery — Discover Specific Process via tasklist + findstr lsass

## Technique Context

T1057 Process Discovery includes targeted variants where the adversary is not enumerating all processes but hunting for a specific one. This test executes `tasklist | findstr lsass`, which is a targeted search for the LSASS (Local Security Authority Subsystem Service) process. LSASS is the highest-value target for credential dumping on Windows — it holds NTLM hashes, Kerberos tickets, and plaintext credentials in memory. Before attempting credential dumping, attackers routinely confirm that LSASS is running, note its PID, and sometimes check its protection level (PPL status).

This targeted form of process discovery is significantly more meaningful than a general `tasklist` run because it directly signals intent. A process search for "lsass" in a scripted or automated context is almost always a precursor to T1003 (OS Credential Dumping) activity. Detection teams treat this as an early warning indicator — even if the credential dump itself fails or is caught, the lsass search establishes context and adversary intent in the timeline.

The addition of `findstr` to filter output is also noteworthy. The command `tasklist | findstr lsass` creates a two-process pipeline: `tasklist.exe` followed by `findstr.exe`. Both processes appear in the telemetry, which means the detection surface expands beyond just `tasklist` to include `findstr` with lsass-related arguments. This provides an additional detection opportunity that general `tasklist` monitoring would miss.

## What This Dataset Contains

The dataset spans three seconds (2026-03-14T23:17:29Z to 23:17:32Z) and records 134 events across three channels: Sysmon (23), PowerShell (105), and Security (6). No Application channel events are present.

**Security EID 4688** records six process creation events that fully document the execution chain:

- `"C:\Windows\system32\whoami.exe"` — pre-test identity check
- `"cmd.exe" /c tasklist | findstr lsass` — the technique invocation via cmd.exe
- `tasklist` — tasklist.exe spawned by cmd.exe
- `findstr  lsass` — findstr.exe spawned by cmd.exe, filtering for "lsass"
- `"C:\Windows\system32\whoami.exe"` — post-test identity check
- `"cmd.exe" /c` — cleanup

The command `findstr  lsass` (note the double space in the captured event) shows the actual filter term. This is the forensic artifact that elevates this test from generic process enumeration to targeted lsass hunting.

**Sysmon EID 1 (ProcessCreate)** captures six process creation events with additional rule tagging. `tasklist.exe` fires `technique_id=T1057,technique_name=Process Discovery`. The `cmd.exe` event fires `technique_id=T1059.003,technique_name=Windows Command Shell`. The `whoami.exe` events fire `technique_id=T1033,technique_name=System Owner/User Discovery`. The `findstr.exe` process creation is also captured.

**Sysmon EID 10 (ProcessAccess)** shows four cross-process access events. The test framework PowerShell opens `whoami.exe` and `cmd.exe` with `GrantedAccess: 0x1FFFFF`. Call traces pass through CLR assemblies — standard ART test framework behavior. No direct process access to `lsass.exe` itself occurs in this test (that would be T1003), but the targeted search establishes the intent for such access.

**Sysmon EID 7 (ImageLoad)** contributes 11 events. These are the standard .NET runtime and Defender DLL loads for the test framework PowerShell process.

**Sysmon EID 17 (PipeCreate)** shows the PowerShell host pipe.

**PowerShell EID 4104** contributes 103 script block events plus 2 EID 4103 module logging events. The framework boilerplate dominates samples, but the technique command (`cmd.exe /c tasklist | findstr lsass`) is present in the Security channel.

Compared to the defended version (31 sysmon, 15 security, 34 PowerShell), the undefended dataset shows fewer Sysmon events (23 vs. 31) and fewer Security events (6 vs. 15). The higher counts in the defended version likely reflect Defender-generated process activity during monitoring.

## What This Dataset Does Not Contain

No events show the output of `tasklist | findstr lsass` — specifically, LSASS's PID and memory usage. In a real attack, this output would be captured and used to target the subsequent credential dump.

No Sysmon EID 22 (DNS) or EID 3 (NetworkConnect) events are present — this is a local-only enumeration step with no network activity.

`findstr.exe` appears in Security EID 4688 but may not have a corresponding Sysmon EID 1 event in the samples, depending on include-mode filter configuration.

## Assessment

This dataset is particularly valuable for detection engineering because it captures the targeted lsass process search pattern, which is a higher-fidelity indicator than generic `tasklist` use. The combination of `tasklist.exe` → `findstr.exe` with a `lsass` argument, spawned by cmd.exe from PowerShell under SYSTEM context, is a compact, specific detection scenario. Both the Security and Sysmon channels provide the necessary field values. The Sysmon rule tagging confirms correct coverage of T1057, T1059.003, and T1033 in the sysmon-modular configuration.

## Detection Opportunities Present in This Data

1. **findstr.exe with "lsass" argument**: Security EID 4688 shows `CommandLine: findstr  lsass`. Any `findstr.exe` execution filtering for "lsass", "lsa", or common LSASS-related strings is a high-fidelity precursor indicator for credential dumping attempts. The argument appears in the `NewProcessCommandLine` field.

2. **tasklist | findstr pipeline in cmd.exe**: The cmd.exe invocation `"cmd.exe" /c tasklist | findstr lsass` is captured in Security EID 4688. Detecting pipe operators in cmd.exe command lines that combine `tasklist` with security-sensitive filter terms is a practical detection approach.

3. **Sysmon EID 1 for findstr.exe with lsass argument**: When Sysmon captures `findstr.exe` process creation with parent `cmd.exe`, and the command line contains `lsass`, this fires regardless of how the command was structured (piped, redirected, etc.).

4. **Three-process chain: powershell → cmd.exe /c tasklist|findstr → tasklist + findstr**: The full process ancestry is present in both Security and Sysmon channels. Detecting this specific process chain, particularly when the grandparent is a script interpreter under SYSTEM, provides high-precision detection with low false positive rate.

5. **Sysmon RuleName=T1057 combined with findstr child**: When `tasklist.exe` fires the T1057 rule tag AND a sibling `findstr.exe` process appears with the same parent cmd.exe, the combination indicates targeted (not general) process enumeration.

6. **Rapid succession of whoami + tasklist + findstr lsass**: The event sequence — `whoami.exe`, then `cmd.exe /c tasklist | findstr lsass`, then `whoami.exe` again — within seconds is a recognizable ART-style discovery pattern. In a real attack, the `whoami` bookends may not be present, but the `tasklist + findstr lsass` sequence in close temporal proximity to other discovery steps remains significant.
