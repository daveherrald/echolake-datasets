# T1218.005-4: Mshta — Invoke HTML Application — Jscript Engine over Local UNC Simulating Lateral Movement

## Technique Context

T1218.005 (Mshta) covers abusing `mshta.exe` to execute arbitrary code. This test uses the `Invoke-ATHHTMLApplication` function from the AtomicTestHarnesses library to invoke mshta.exe against an HTA file referenced via a local UNC path with the JScript engine. The `-AsLocalUNCPath` flag causes the HTA to be referenced as `\\hostname\share\Test.hta` rather than a local file path, simulating the lateral movement scenario where an attacker distributes a malicious HTA file on a network share and invokes it via mshta.exe on a remote host.

The full technique invocation is: `Invoke-ATHHTMLApplication -HTAFilePath Test.hta -ScriptEngine JScript -AsLocalUNCPath -SimulateLateralMovement -MSHTAFilePath $env:windir\system32\mshta.exe`. The UNC path approach is relevant because defenders who restrict mshta.exe from loading local files may still allow UNC paths, and the network-path execution leaves a different artifact trail than a local file reference.

## What This Dataset Contains

The dataset spans 3 seconds (2026-03-17T16:56:02Z to 16:56:05Z) across 149 total events: 108 PowerShell, 4 Security, 37 Sysmon.

**Technique invocation command in Sysmon EID 1:** The child PowerShell process (PID 17760) carries the technique function call in its command line:

```
"powershell.exe" & {Invoke-ATHHTMLApplication -HTAFilePath Test.hta -ScriptEngine JScript -AsLocalUNCPath -SimulateLateralMovement -MSHTAFilePath $env:windir\system32\mshta.exe}
```

Sysmon captures this with RuleName `technique_id=T1083,technique_name=File and Directory Discovery` — the same sysmon-modular PowerShell LOLBin include rule that fired on similar tests.

**Process chain (Security EID 4688):** The test framework spawned two child PowerShell processes (PIDs 0x4560 and 0x47d0) and two whoami.exe processes (PIDs 0x4004 and 0x45fc) from the parent test framework PowerShell (PID 0x4504). All run as SYSTEM. The two PowerShell children represent the technique invocation and the cleanup phase.

**Cleanup PS block (EID 4104):** The cleanup block `Invoke-AtomicTest T1218.005 -TestNumbers 4 -Cleanup -Confirm:$false` was captured, confirming the test framework completed its full lifecycle.

**Sysmon image loads (EID 7, 25 total):** The standard .NET runtime DLL set loading into the test framework PowerShell sessions.

**Process access events (Sysmon EID 10, 4 events):** PowerShell accessing its child processes with full access rights.

**Named pipe creation (Sysmon EID 17, 3 events):** Three PowerShell host pipes, confirming three distinct PowerShell host sessions (test framework, technique invocation, cleanup).

## What This Dataset Does Not Contain

**No `mshta.exe` process creation event.** Neither the Security EID 4688 nor Sysmon EID 1 records show `mshta.exe` executing. In the defended variant (36 Sysmon, 10 Security, 45 PowerShell events), mshta.exe also does not appear — Defender blocked the execution. The undefended dataset similarly lacks mshta.exe, which suggests the test artifact `Test.hta` was not present at the required path when the test ran, rather than Defender blocking it.

Also absent:
- No Sysmon EID 3 network connections to UNC paths
- No file creation for a `.hta` file
- No DNS queries for the local UNC hostname
- No JScript engine activity

## Assessment

This dataset does not capture a successful mshta.exe UNC execution. The pattern — test framework invocation, technique function call in PowerShell command line, cleanup — without any `mshta.exe` process create or UNC network activity — matches T1218.001-7 and T1218.005-3 in being a test where the ART test framework function encountered a missing test artifact (likely `Test.hta` not present). `Invoke-ATHHTMLApplication` would return without invoking mshta.exe if the specified HTA file path cannot be resolved.

The defended and undefended variants are nearly identical in structure: both show the test framework PowerShell invocation of `Invoke-ATHHTMLApplication` but neither captures `mshta.exe` execution. The undefended run has slightly more PowerShell volume (108 vs. 45 events) due to absent AMSI filtering.

## Detection Opportunities Present in This Data

**`Invoke-ATHHTMLApplication` with UNC and JScript flags in PowerShell command line (Sysmon EID 1):** The presence of `-AsLocalUNCPath`, `-SimulateLateralMovement`, and `-ScriptEngine JScript` in a PowerShell command line reveals the technique intent even without the downstream mshta.exe execution. Real attacker tooling would obfuscate these argument names.

**`mshta.exe` executing from a UNC path (Sysmon EID 1, Security EID 4688 — when execution occurs):** When this test executes successfully, the expected mshta.exe command line would reference a `\\hostname\share\` path. Mshta.exe with a UNC path argument is rare in legitimate usage and should trigger investigation, particularly when invoked from PowerShell or a script host.

**`mshta.exe` executing JScript content from a network path (Sysmon EID 3):** A successful run would show mshta.exe establishing a network connection to resolve the UNC server, distinct from a remote HTTP(S) download. This network connection from mshta.exe to a file server (as opposed to a web server) indicates the file-share distribution variant of this technique.
