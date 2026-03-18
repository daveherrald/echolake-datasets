# T1105-11: Ingress Tool Transfer — OSTAP Worming Activity

## Technique Context

T1105 (Ingress Tool Transfer) covers adversary techniques for moving tools, payloads, and files into a compromised environment. OSTAP (a JavaScript-based downloader and worm associated with the TrickBot/BazarLoader ecosystem) is notable for its network share propagation mechanism: it copies itself to accessible network shares and mapped drives to spread laterally within an organization, using Windows Script Host (WSH/CScript) to execute JavaScript dropper code.

The OSTAP propagation pattern is distinctive: it uses `cmd.exe` to push to a UNC path (using `pushd \\server\share` to mount it as a drive letter), writes a JavaScript file to that share via `echo > file.js`, executes it with `CScript.exe //E:JScript`, then deletes both the script and any created artifacts before disconnecting. The entire chain runs within a single `cmd.exe /c` command, making it fast and leaving minimal persistent artifacts on disk.

This test simulates the OSTAP worm behavior by pushing to `\\localhost\C$` (the local admin share, accessible to SYSTEM), dropping a JavaScript file that creates a marker file, executing it with CScript, then cleaning up — demonstrating the complete file-write-execute-delete cycle that OSTAP uses to spread payloads.

## What This Dataset Contains

The dataset spans approximately fifteen seconds (2026-03-14T23:39:17Z–23:39:32Z) on ACME-WS06.acme.local and contains 130 events across five channels.

**The core OSTAP simulation command** is fully captured in Security EID 4688 (cmd.exe, from PowerShell parent):

```
"cmd.exe" /c pushd \\localhost\C$ & echo var fileObject = WScript.createobject("Scripting.FileSystemObject");
var newfile = fileObject.CreateTextFile("AtomicTestFileT1105.js", true);
newfile.WriteLine("This is an atomic red team test file for T1105. It simulates how OSTap worms accross network shares and drives.");
newfile.Close(); > AtomicTestT1105.js & CScript.exe AtomicTestT1105.js //E:JScript
& del AtomicTestT1105.js /Q >nul 2>&1 & del AtomicTestFileT1105.js /Q >nul 2>&1 & popd
```

This single `cmd.exe` command:
1. `pushd \\localhost\C$` — mounts the local admin share as a drive letter (requires SYSTEM or admin access)
2. `echo var fileObject...` — writes a JavaScript dropper script (`AtomicTestT1105.js`) to the current directory on the share
3. `CScript.exe AtomicTestT1105.js //E:JScript` — executes the script with Windows Script Host in JScript mode
4. `del AtomicTestT1105.js` and `del AtomicTestFileT1105.js` — deletes both the script and the file it created
5. `popd` — unmounts the share

The JavaScript itself creates a text file `AtomicTestFileT1105.js` with a descriptive payload string — a benign marker file representing what would be a malicious payload in a real OSTAP deployment.

**Security EID 4688** also captures:
- `svchost.exe -k netsvcs -p -s BITS` — Background Intelligent Transfer Service (BITS) starting, triggered by the test. BITS is used by malware families for stealthy downloads; its activation here may be incidental or may be triggered by the network share access.
- `whoami.exe` — test framework checks
- `CScript.exe AtomicTestT1105.js //E:JScript` — the JavaScript execution

**Sysmon EID 1** (2 events): `cscript.exe` (PID parent `cmd.exe`, rule `technique_id=T1059.003`) and `whoami.exe` (rule `T1033`). The cscript execution with `//E:JScript` explicit engine specifier is captured, confirming the JavaScript dropper ran.

**Security EID 4624** and **EID 4672**: a SYSTEM account logon (Type 5, service logon) with special privileges assigned, occurring when the BITS service starts. This is ambient system activity.

**Security EID 4799** (2 events): local group membership enumeration of `Administrators` (S-1-5-32-544) and `Backup Operators` (S-1-5-32-551) by `svchost.exe`. This is consistent with the BITS service startup querying local group memberships as part of its initialization — background OS telemetry.

**Sysmon EID 7** (15 events): DLL loads for PowerShell.

**Sysmon EID 10** (3 events): PowerShell accessing child processes.

**Sysmon EID 17** (1 event): PowerShell named pipe creation.

**System channel EID 7040**: `The start type of the Background Intelligent Transfer Service service was changed from demand start to auto start` — BITS service startup type change triggered by the network share access. In real OSTAP deployments, BITS is used as a download mechanism; seeing it activate during file transfer activity adds contextual interest.

**WMI channel EID 5860**: `Namespace = ROOT\CIMV2; NotificationQuery = SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'wsmprovhost.exe'` — a WMI subscription watching for WinRM Provider Host process starts, consistent with system WMI monitoring activity.

**PowerShell EID 4104** (93 events): script blocks for the test framework and cleanup.

## What This Dataset Does Not Contain

No file creation events (Sysmon EID 11) are captured for `AtomicTestT1105.js` or `AtomicTestFileT1105.js` being written to the share. The script's cleanup (`del`) ensures the files are removed quickly, and the Sysmon EID 11 sample likely missed this transient file creation. In a real OSTAP deployment, the brief file existence window is intentional — the dropper runs and self-deletes before defenders can react.

No network connection events (Sysmon EID 3) appear for the `\\localhost\C$` SMB access. Sysmon typically captures TCP connections but loopback SMB to localhost may not generate a network event, and the sample set did not include any from this channel.

No DNS events capture the share access. The `pushd \\localhost\C$` is a local loopback SMB connection and would not generate external DNS queries.

## Assessment

With Defender disabled, the entire OSTAP simulation chain ran successfully: the share was mounted, the JavaScript was written, executed by CScript, and cleaned up. The complete command line is preserved in Security EID 4688 — including the inline JavaScript content embedded in the `echo` statement. This is a rich telemetry record of the OSTAP behavioral pattern.

The BITS service startup (EID 7040, Security 4624/4672, Security 4799) provides realistic ambient context: a defender investigating this event stream would need to determine whether the BITS activation was triggered by the share access or was coincidental background activity. This ambiguity is realistic — OSTAP's actual loader variants do use BITS for subsequent payload downloading.

Compared to the defended variant (37 Sysmon, 14 Security, 34 PowerShell), the undefended dataset is slightly smaller in Sysmon (24 vs. 37) but adds System (1) and WMI (1) channel coverage not present in the defended summary. The defended variant's higher Sysmon count reflects Defender inspection activity.

## Detection Opportunities Present in This Data

**`pushd \\server\share` + `echo` + CScript in single cmd.exe command**: Security EID 4688 preserves the full compound command including the UNC path mount, inline JavaScript creation, and `CScript.exe //E:JScript` execution as a single `cmd.exe /c` invocation. This compound pattern is highly specific to OSTAP and similar share-based droppers.

**CScript.exe with non-absolute .js file path**: Sysmon EID 1 captures `CScript.exe AtomicTestT1105.js //E:JScript` without an absolute path — the script is executed from the current directory on the mounted share. `CScript.exe` running against a `.js` file from a non-absolute path, particularly after a `pushd \\` command, is a strong behavioral indicator.

**`//E:JScript` explicit engine specifier**: Most legitimate CScript usage does not require explicitly specifying JScript as the engine; this argument is characteristic of OSTAP and other WSH-based droppers that need to ensure their JavaScript runs in the correct engine context.

**BITS service activation concurrent with network share enumeration**: The System EID 7040 BITS service type change coinciding with share-based file operations connects two behaviors associated with OSTAP's download mechanism. Correlating BITS activation with share-based JavaScript execution is a useful behavioral chain.

**`del` cleanup after CScript execution in the same cmd.exe**: The delete operations for both the script and its output file within the same command chain is a self-cleanup pattern. Process-level monitoring that sees `echo > file.js && CScript.exe file.js && del file.js` in a single command is reliably distinguishing malicious dropper behavior from legitimate scripting.
