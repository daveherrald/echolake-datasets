# T1548.002-10: Bypass User Account Control — UACME Method 23

## Technique Context

T1548.002 (Bypass User Account Control) covers techniques that allow attackers to escalate from a standard user to an administrator context without triggering the Windows UAC elevation prompt. UACME (User Account Control Exploit) is an open-source research toolkit (`Akagi64.exe`) that catalogs dozens of distinct UAC bypass techniques, each using a different Windows subsystem vulnerability.

Method 23 exploits the `ISecurityEditor` COM interface exposed by the Windows Setup API. This interface can modify DACL (discretionary access control list) entries on HKLM registry keys without requiring elevation, because it runs in the context of a trusted auto-elevating COM server. By manipulating DACLs on specific registry keys, an attacker can plant a malicious value that gets loaded by an auto-elevating process, achieving elevated execution. The test invokes `Akagi64.exe` with method number 23 as an argument.

This dataset captures the **undefended** execution on ACME-WS06 with Defender disabled. The defended variant (ACME-WS02, Defender active) showed 26 sysmon, 11 security, 34 powershell, 1 system, and 1 wmi event — compared to the undefended 16 sysmon, 3 security, and 96 powershell. The **defended dataset actually has more events**, because Defender's process interrogation and monitoring overhead adds additional process access and file events even when it ultimately fails to produce a block. The undefended dataset is more streamlined: Akagi64.exe ran without Defender interference.

## What This Dataset Contains

The dataset spans approximately 4 seconds on ACME-WS06 and contains 115 events across three log sources.

**Sysmon (16 events, EIDs 1, 7, 10, 17):**

- **EID 1 (ProcessCreate):** Three events:
  1. `whoami.exe` (tagged `T1033`) — ART test framework pre-check
  2. `cmd.exe` (tagged `T1059.003`) with command line:
     ```
     "cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\uacme\23 Akagi64.exe"
     ```
     This is the invocation of UACME Method 23. The path shows the ART ExternalPayloads directory structure and the method number as an argument to `Akagi64.exe`.
  3. A second `whoami.exe` — ART test framework post-check

- **EID 10 (ProcessAccess):** Three events tagged `T1055.001 Dynamic-link Library Injection` — the test framework PowerShell process (parent) acquiring handles to `whoami.exe` and `cmd.exe` with `GrantedAccess: 0x1FFFFF` (full access). This is a consistent test framework artifact, not evidence of injection.

- **EID 17 (PipeCreate):** One named pipe creation event for the PowerShell host runtime.

- **EID 7 (ImageLoad):** Nine DLL load events for PowerShell initialization.

**No Sysmon EID 1 for Akagi64.exe itself.** The sysmon-modular include-mode ProcessCreate configuration does not have a rule matching `Akagi64.exe` or the ExternalPayloads path. `cmd.exe` was captured by the T1059.003 rule, but Akagi64.exe's process creation did not match any include rule. In the undefended environment, Akagi64.exe executed — but Sysmon did not capture its process create event.

**Security (3 events, all EID 4688):** Process creation records for `whoami.exe` (once) and `cmd.exe` with the Akagi64.exe invocation:

```
NewProcessName: C:\Windows\System32\cmd.exe
CommandLine: "cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\uacme\23 Akagi64.exe"
```

Security EID 4688 also does not capture `Akagi64.exe` itself. This is consistent with the Sysmon gap: neither the Sysmon include-mode config nor the Security audit policy produced a record for the UACME binary process creation.

**PowerShell (96 events, EIDs 4104 × 95, 4103 × 1):** Entirely ART test framework boilerplate — `Set-StrictMode`, `Set-ExecutionPolicy -Bypass`, error-formatting scriptblocks. The technique was invoked via `cmd.exe`, not PowerShell. The 95 EID 4104 events provide no attack-specific content.

## What This Dataset Does Not Contain

**No Akagi64.exe process creation record.** In the undefended environment, Akagi64.exe ran. But neither Sysmon EID 1 nor Security EID 4688 captured its process creation. This is a monitoring gap: the ExternalPayloads directory and `Akagi64.exe` filename are not in any sysmon-modular include rule, and the Security audit policy's process creation logging did not produce an event for it within the captured window.

**No UAC bypass execution chain.** The full Method 23 bypass — DACL manipulation, auto-elevation trigger, elevated process spawn — is not visible in this dataset. No elevated process (token type 2) creation events appear in the Security or Sysmon channels.

**No registry modification events.** Method 23 would manipulate HKLM DACL entries; no Sysmon EID 13 or Security EID 4657 events are present.

**No file system artifacts.** No EID 11 (FileCreate) events for Method 23's potential DLL staging are present.

## Comparison with Defended Dataset

The defended dataset for this test (T1548.002-10 from ACME-WS02) is structurally similar at the top level: both show the `cmd.exe` invocation of Akagi64.exe. In the defended environment, Defender's real-time protection was active but did **not** block the binary at the point of invocation — Defender's interference manifested as additional WMI and System events (a WMI query subscription, a BITS service state change) from the behavioral monitoring infrastructure spinning up. In the undefended environment, these Defender artifacts are absent, but the core bypass execution is equally invisible to Sysmon and Security audit logging.

The implication is that for UACME Method 23, the primary detection gap is in process creation logging of the UACME binary itself — which is absent in both environments.

## Assessment

This dataset documents the invocation of UACME Method 23 at the `cmd.exe` level. The `cmd.exe` process and its invocation path (`ExternalPayloads\uacme\23 Akagi64.exe`) are captured in both Sysmon EID 1 and Security EID 4688. Beyond this, the dataset contains no evidence of the bypass execution chain.

In the undefended environment, Akagi64.exe ran — but its execution is invisible to the configured logging. This makes the `cmd.exe` invocation record the primary (and only actionable) forensic artifact. Any investigation of this technique must anchor on the `cmd.exe` command line and work backward from there.

## Detection Opportunities Present in This Data

- **Security EID 4688 and Sysmon EID 1:** `cmd.exe` launched from PowerShell or other scripting hosts with a command line containing `Akagi64.exe`, `uacme`, or references to the ExternalPayloads directory path pattern. The filename `Akagi64.exe` is a well-known UACME binary name and should be treated as an alert trigger in any process creation log.

- **Sysmon EID 1 process creation rules:** Adding `Akagi64.exe` (and variant names: `Akagi.exe`, `uacme.exe`) as explicit include patterns to the sysmon-modular ProcessCreate configuration would capture the UACME binary process creation that is currently missing.

- **Path pattern:** The `ExternalPayloads` directory path embedded in the `cmd.exe` command line is a distinctive ART artifact. In real-world use, UACME would be invoked from an attacker-controlled path — monitoring for `Akagi64.exe` in any path context is the more durable approach.

- **UAC bypass behavioral detection:** Monitoring for auto-elevating processes (`mmc.exe`, `eventvwr.exe`, `fodhelper.exe`, etc.) spawning unexpected children would detect successful Method 23 bypass execution. The absence of such events here indicates the bypass may not have fully succeeded in this test run.

- **Token elevation correlation:** Security EID 4688 records include the `TokenElevationType` field. Processes with `TokenElevationType: %%1937` (elevated token, type 2) spawned without a corresponding UAC consent prompt process (`consent.exe`) are indicators of UAC bypass.
