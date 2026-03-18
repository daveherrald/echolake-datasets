# T1110.003-8: Password Spraying — Password Spray using Kerbrute Tool

## Technique Context

Password spraying (T1110.003) is typically associated with PowerShell-based LDAP tools in Windows environments, but native binary tools offer attackers meaningful advantages: no script block logging, no PowerShell engine to inspect, and execution patterns closer to compiled applications. Kerbrute is a Go-compiled binary that performs Kerberos pre-authentication attacks directly over UDP/TCP port 88, bypassing the LDAP-based authentication paths that most workstation-side spray detection targets.

The Kerberos approach makes Kerbrute attractive for several reasons. Kerberos pre-authentication failures (EID 4771 on the DC) are generated per-attempt, but the workstation generates no process-level authentication event — the spray traffic goes directly from the workstation to the DC's port 88. Kerbrute also supports username enumeration without authentication, meaning an attacker can validate account existence before attempting authentication. In this test the spray is performed with password `password132` against a user list pre-staged at `C:\AtomicRedTeam\atomics\..\ExternalPayloads\passwordspray.txt`.

The critical observation in this dataset is that **Kerbrute's binary execution does not appear in the Sysmon process create (EID 1) or Security EID 4688 telemetry** — despite the PowerShell command instructing it to run. This gap is discussed in detail below.

## What This Dataset Contains

This dataset captures 147 events across three channels (1 Application, 105 PowerShell, 4 Security, 38 Sysmon) collected over a 3-second window (2026-03-14T23:48:32Z–23:48:35Z) on ACME-WS06 with Defender disabled.

**Application Channel (EID 15):**
One EID 15 event: `Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON` — test framework artifact from the Defender toggle.

**Process Creation Chain (Security EID 4688 and Sysmon EID 1):**

Security EID 4688 records four process creations:
1. `whoami.exe` — pre-test identity check
2. The attack PowerShell child process with command:
   ```
   "powershell.exe" & {cd "C:\AtomicRedTeam\atomics\..\ExternalPayloads\"
   .\kerbrute.exe passwordspray --dc $ENV:userdnsdomain -d $ENV:userdomain "C:\AtomicRedTeam\atomics\..\ExternalPayloads\passwordspray.txt" password132}
   ```
3. `whoami.exe` — post-test identity check
4. An empty PowerShell cleanup stub: `"powershell.exe" & {}`

Sysmon EID 1 captures the same attack PowerShell process (PID 5408) with the full command line, SHA256 hash of `powershell.exe` (`D783BA6567FAF10FDFF2D0EA3864F6756862D6C733C7F4467283DA81AEDC3A80`), IMPHASH `E09C4F82A1DA13A09F4FF2E625FEBA20`, parent process GUID, and integrity level (System). The `whoami.exe` process creates are also captured (PID 4016), tagged with `technique_id=T1033`.

**The Kerbrute Binary Does Not Appear:**

Despite the command instructing the child PowerShell to `cd` to the `ExternalPayloads` directory and run `.\kerbrute.exe`, there is no EID 1 or EID 4688 event for `kerbrute.exe`. This reflects the Sysmon configuration in use: the `sysmon-modular` configuration uses include-only rules for process creation, matching on known LOLBins and suspicious patterns. `kerbrute.exe` with a generic name does not match these include rules, so Sysmon did not record its creation.

Security EID 4688 uses audit policy configured for process creation auditing, but the Sysmon configuration's process create rules are not the same as the Security log — the Security log records all process creations when `Audit Process Creation` is set to `Success`. The absence of `kerbrute.exe` in EID 4688 therefore suggests the binary either was not present in `ExternalPayloads` (the prerequisite was not met), or that the `cd` resolved to a path that didn't contain the binary and PowerShell silently exited. Given the ExternalPayloads directory is expected to contain kerbrute.exe as an ART prerequisite, this is consistent with the prerequisite check not completing or the binary not being at the expected path.

**PowerShell Script Block Logging (EID 4104):**

105 EID 4104 events, all PowerShell internal boilerplate. Because the attack command is `.\kerbrute.exe` (a binary), no PowerShell functions are compiled and no substantive script block content beyond the command line itself is generated.

**Sysmon Image Loads (EID 7):**

25 EID 7 events for the .NET CLR DLL load sequence on the attack PowerShell process (PID 5728).

**Sysmon Named Pipe Creates (EID 17):**

Three EID 17 events for standard PowerShell `\PSHost.*` named pipes.

## What This Dataset Does Not Contain

- **Kerbrute.exe process creation:** The binary is either absent or Sysmon's include filter did not capture it. This is a significant coverage gap for binary-based Kerberos spraying tools.
- **Kerberos authentication events (EID 4771):** These would appear on ACME-DC01, not on the workstation. DC-side telemetry is not part of this dataset.
- **Network connections to the DC on port 88:** Sysmon EID 3 events for Kerberos traffic are absent. If Kerbrute had run, EID 3 events would show TCP/UDP connections to the DC from the workstation.
- **File access events for the password list:** The `C:\AtomicRedTeam\atomics\..\ExternalPayloads\passwordspray.txt` file access would only appear if file object auditing was enabled (it is not in this configuration).

## Assessment

This dataset illustrates an important detection gap: when an attack uses a compiled binary with a non-LOLBin name, Sysmon's include-only process create filtering misses it entirely. The workstation telemetry shows the PowerShell test framework command that would invoke Kerbrute, but provides no direct evidence of Kerbrute running. An analyst examining only this dataset would see a suspicious PowerShell command referencing `kerbrute.exe` and an `ExternalPayloads` directory, but would not see the actual spray execution.

Compared to the defended variant (81 events: 43 PowerShell, 12 Security, 26 Sysmon), the undefended version (147 events) is larger primarily due to the higher PowerShell EID 4104 count (105 vs. 43) from the uninterrupted PowerShell session. The Security channel count (4 vs. 12) is lower here — the defended variant captured more Security events from Defender's detection process activity.

The dataset's primary value is in demonstrating the coverage gap for binary Kerberos tools, and in providing the complete PowerShell command line for the kerbrute invocation including the exact flag syntax (`passwordspray --dc ... -d ... <userlist> <password>`).

## Detection Opportunities Present in This Data

**EID 4688 / Sysmon EID 1 — Command Line References kerbrute.exe:**
The child PowerShell command line references `kerbrute.exe`, `passwordspray`, `--dc`, and `ExternalPayloads`. The string `kerbrute` in any process creation command line is a high-fidelity indicator regardless of whether the binary itself is captured.

**EID 4688 — PowerShell Command Changing Directory to ExternalPayloads:**
A PowerShell command that `cd`s to `ExternalPayloads` and invokes a relative binary path (`.\kerbrute.exe`) is a pattern common to ART-based attack frameworks. The `ExternalPayloads` path is a well-known ART artifact path and can be used as a triage indicator.

**Absence of EID 1/4688 for the Binary as an Indicator:**
The absence of a process creation event for `kerbrute.exe` following the PowerShell command that should invoke it is itself informative — it either means the binary wasn't present (failed prerequisite), or your monitoring has a gap. This pattern of "command references binary, but binary never creates a process record" is worth incorporating as a gap analysis check in detection validation.

**DC-Side Coverage Requirement:**
This dataset highlights that workstation-only telemetry is insufficient for detecting Kerberos-based spraying. EID 4771 (Kerberos pre-auth failure) on ACME-DC01 would be the definitive evidence if Kerbrute ran successfully. Pairing workstation process telemetry with DC-side Kerberos audit logs provides the full picture.
