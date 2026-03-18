# T1110.004-4: Credential Stuffing — Brute Force: Credential Stuffing using Kerbrute Tool

## Technique Context

Credential stuffing (T1110.004) is a variant of the brute force technique family where an adversary uses lists of known username/password combinations — typically sourced from prior data breaches — to attempt authentication against target systems. Unlike password spraying (T1110.003) which distributes a single password across many accounts, credential stuffing pairs specific usernames with specific passwords that are known to have belonged to those users in other systems, exploiting password reuse across services.

Kerbrute's `bruteforce` mode is the operational capability here, distinct from its `passwordspray` mode used in T1110.003-8. The bruteforce mode reads a file of `username:password` pairs from `C:\AtomicRedTeam\atomics\..\ExternalPayloads\bruteforce.txt` and attempts Kerberos pre-authentication for each pair. The attack targets Active Directory accounts directly over Kerberos (port 88) from the workstation, with no LDAP involvement.

The same binary coverage gap present in T1110.003-8 applies here: the Kerbrute binary's execution is not captured in process creation telemetry due to the Sysmon include-only configuration. However, this dataset adds a notable element absent from T1110.003-8: a Sysmon EID 3 network connection event that partially documents the network activity occurring during the test window.

## What This Dataset Contains

This dataset captures 149 events across three channels (105 PowerShell, 4 Security, 40 Sysmon) collected over a 3-second window (2026-03-14T23:48:43Z–23:48:46Z) on ACME-WS06 with Defender disabled.

**Process Creation Chain (Security EID 4688 and Sysmon EID 1):**

Security EID 4688 records four process creations:
1. `whoami.exe` — pre-test identity check
2. The attack PowerShell child process (PID 800) with command:
   ```
   "powershell.exe" & {cd "C:\AtomicRedTeam\atomics\..\ExternalPayloads\"
   .\kerbrute.exe bruteforce --dc $ENV:userdnsdomain -d $ENV:userdomain "C:\AtomicRedTeam\atomics\..\ExternalPayloads\bruteforce.txt"}
   ```
3. `whoami.exe` — post-test identity check
4. An empty PowerShell cleanup stub: `"powershell.exe" & {}`

Sysmon EID 1 captures the attack PowerShell process (PID 800) with the full command line. The `CommandLine` field clearly shows the `kerbrute.exe bruteforce` invocation with the credential file path. Hash data: SHA256 `D783BA6567FAF10FDFF2D0EA3864F6756862D6C733C7F4467283DA81AEDC3A80`, IMPHASH `E09C4F82A1DA13A09F4FF2E625FEBA20`, parent GUID `{9dc7570a-f3da-69b5-7911-000000000600}`.

**Sysmon Network Connection (EID 3):**

One EID 3 network connection event is present, but it is **not** from Kerbrute. It records an outbound TCP connection from `MpDefenderCoreService.exe` (Windows Defender's core service, PID 5916) to `51.116.246.105:443` from source IP `192.168.4.16` (ACME-WS06's IP). This is a Defender telemetry/cloud lookup connection initiated at `2026-03-14T23:48:35Z` — 7 seconds before this test's window. It is tagged by Sysmon rule `technique_id=T1036,technique_name=Masquerading`, which reflects the sysmon-modular rule matching on network connections from processes in non-standard paths (`ProgramData\Microsoft\Windows Defender`). This is a false-positive rule match; the actual activity is legitimate Defender cloud connectivity.

No EID 3 events for Kerbrute itself (expected port 88 TCP/UDP to ACME-DC01 at 192.168.4.10) appear in this dataset.

**Sysmon Image Loads (EID 7):**

25 EID 7 events for the .NET CLR DLL load sequence on the attack PowerShell process (PID 3656): `mscoree.dll`, `mscoreei.dll`, `clr.dll`, `mscorlib.ni.dll`, `System.Management.Automation.ni.dll`.

**Sysmon Process Creates (EID 1):**

4 EID 1 events: `whoami.exe` (pre-test), the attack PowerShell process, and 2 more process creates from the cleanup phase.

**Sysmon Named Pipe Creates (EID 17) and File Creates (EID 11):**

3 EID 17 events for standard PowerShell `\PSHost.*` named pipes. 2 EID 11 file creation events from `MsMpEng.exe` creating temporary files in `C:\Windows\Temp\` — Defender test framework artifacts.

**PowerShell Script Block Logging (EID 4104):**

105 EID 4104 events, all PowerShell runtime boilerplate. As with T1110.003-8, the actual attack is a binary invocation and generates no substantive PowerShell function compilation.

## What This Dataset Does Not Contain

- **Kerbrute.exe process creation:** The binary is not captured in EID 1 or EID 4688 for the same reason as T1110.003-8 — either the binary was absent (prerequisite failure) or Sysmon's include filter excluded it.
- **Kerberos authentication events on the DC:** EID 4768 (TGT request) and EID 4771 (Kerberos pre-auth failure) would appear on ACME-DC01 if Kerbrute ran and made authentication attempts. These are not present in workstation telemetry.
- **Network connections to the DC on port 88:** No EID 3 events show TCP/UDP connections from ACME-WS06 to ACME-DC01. This is consistent with Kerbrute either not executing or executing outside the Sysmon EID 3 capture window.
- **The contents of `bruteforce.txt`:** The credential list file path is visible in the command line, but the file's contents are not accessible from process telemetry without file content auditing.

## Assessment

T1110.004-4 and T1110.003-8 are closely related datasets — both use Kerbrute, both have the same binary visibility gap, and both show the attack command in the PowerShell process creation chain. The key differentiator is the mode (`bruteforce` vs. `passwordspray`) and the input file format: `bruteforce.txt` contains `username:password` pairs (known breach credentials), while `passwordspray.txt` contains usernames only.

Compared to the defended variant (80 events: 42 PowerShell, 12 Security, 26 Sysmon), this undefended dataset (149 events) is again larger primarily due to the higher PowerShell EID 4104 count from uninterrupted execution.

The Defender cloud connection (EID 3, destination `51.116.246.105:443`) appearing in this dataset's collection window is an important example of ambient background network activity that will be present in any real-world dataset — the workstation makes cloud service connections continuously regardless of whether an attack is occurring. This event is correctly attributed to `MpDefenderCoreService.exe` by image path, but the misleading `T1036 Masquerading` rule tag demonstrates that Sysmon rule annotations require validation before treating them as definitive technique classifications.

## Detection Opportunities Present in This Data

**EID 4688 / Sysmon EID 1 — Command Line References kerbrute.exe bruteforce:**
The full Kerbrute command line including `bruteforce`, `--dc`, `-d`, and the `ExternalPayloads\bruteforce.txt` path is captured in process creation telemetry. The `bruteforce` subcommand combined with `kerbrute` is a specific enough string for high-confidence matching.

**EID 4688 — ExternalPayloads Directory Reference:**
The `C:\AtomicRedTeam\atomics\..\ExternalPayloads\` path appearing in a PowerShell command line is an ART-specific indicator. In a real environment, any reference to this path in process creation events indicates the ART framework is active.

**Sysmon EID 3 — Baseline Establishment:**
The Defender cloud connection to `51.116.246.105:443` in this dataset provides an example of the background network activity pattern. Establishing baselines for expected `MpDefenderCoreService.exe` and `MsMpEng.exe` network destinations helps distinguish defender telemetry from malicious outbound connections.

**Cross-Dataset Comparison with T1110.003-8:**
Having both kerbrute password spray (T1110.003-8) and kerbrute bruteforce (T1110.004-4) datasets from the same environment allows direct comparison of the command structures. The only meaningful command-line difference is `passwordspray ... password132` vs. `bruteforce` with a combined credential file — a distinction that matters for behavioral classification.
