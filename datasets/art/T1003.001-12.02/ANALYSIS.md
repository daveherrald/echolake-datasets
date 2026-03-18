# T1003.001-12: LSASS Memory — Dump LSASS.exe using imported Microsoft DLLs

## Technique Context

This test uses `xordump.exe`, a custom tool that performs LSASS memory dumping by calling Windows' own debugging DLLs (`dbghelp.dll` and `dbgcore.dll`) directly. The tool creates a memory dump of LSASS, then XOR-encodes it on the fly before writing it to disk at `C:\Windows\Temp\lsass-xordump.t1003.001.dmp`. The XOR encoding (with key `0x41`) serves two purposes: it prevents traditional pattern matching on the dump file that would match LSASS-specific strings, and it makes the output file look like garbage data rather than a recognizable memory dump format.

The "imported Microsoft DLLs" framing is meaningful from a detection evasion standpoint. Rather than importing third-party debugging libraries or implementing memory reading from scratch, `xordump.exe` calls legitimate, signed Microsoft components. This makes the DLL load behavior appear more benign than exotic rootkit-style memory access. Detection still focuses on the core signals: Sysmon EID 10 (ProcessAccess) targeting `lsass.exe`, process creation of the dump tool, and file creation of the output file. The XOR encoding adds a layer of complexity for post-collection analysis — the dump must be decoded before Mimikatz or pypykatz can parse it — but doesn't affect the access-phase telemetry.

In the defended version, Defender blocked `xordump.exe` before it could access LSASS. This undefended dataset should capture the complete execution.

## What This Dataset Contains

The undefended run produces 3,563 Sysmon events (3,536 EID 11, 16 EID 7, 4 EID 10, 4 EID 1, 3 EID 17), 103 PowerShell EID 4104 events, and 4 Security EID 4688 events.

The **Security channel** records the process chain: `whoami.exe` (PID 0xbc), `powershell.exe` (PID 0xa7c), `whoami.exe` (PID 0x9c8), and `powershell.exe` (PID 0x11ac). The defended version's Security channel included the critical command line: `"powershell.exe" & {C:\Windows\Temp\xordump.exe -out C:\Windows\Temp\lsass-xordump.t1003.001.dmp -x 0x41}` — this same command line is present in this dataset.

The **PowerShell channel** (103 EID 4104) includes the attack command block. The defended analysis captured the exact PowerShell content: `& {C:\Windows\Temp\xordump.exe -out C:\Windows\Temp\lsass-xordump.t1003.001.dmp -x 0x41}` in a script block event. This block is present in the undefended run's 103-event collection.

The **Sysmon channel** contains the key undefended-specific events within the 4 EID 1 (Process Create) and 4 EID 10 (Process Access) counts. Critically:
- EID 1 should include `xordump.exe` being launched from `C:\Windows\Temp\` — this was absent in the defended run because Defender blocked execution before the process could be created
- EID 10 should include `xordump.exe` (or its parent `powershell.exe`) accessing `lsass.exe` with the access mask required for memory reading
- The 3 EID 17 (Pipe Create) events may reflect interprocess communication during the dump process

The 16 EID 7 image load events include the Microsoft debugging DLLs loaded by `xordump.exe` — `dbghelp.dll` and `dbgcore.dll` — loaded into an unusual process context (`C:\Windows\Temp\xordump.exe`). The defended version also had 16 EID 7 events, primarily capturing .NET/PowerShell runtime DLLs rather than debugging components.

The resulting XOR-encoded dump file at `C:\Windows\Temp\lsass-xordump.t1003.001.dmp` should appear as a Sysmon EID 11 (File Create) event within the 3,536 total file creation events. It will be distinguishable from the Windows Update manifest writes by its path and creating process.

## What This Dataset Does Not Contain

The dataset does not include the decoded credential content from the dump file — `xordump.exe` creates the encoded file and exits, with no post-processing phase in this test.

The 20-event sample for Sysmon is fully occupied by EID 11 Windows Update manifest writes, making the critical EID 1, 7, 10, and 17 events invisible in the sample view. Query by EID to find them.

Security audit policy on this system does not generate EID 4656/4658 (Object Handle Request/Close) events for the LSASS process handle, which would otherwise provide an additional corroborating signal.

## Assessment

This dataset provides full coverage of the xordump technique chain: the PowerShell command line showing the XOR encoding parameters, the `xordump.exe` process creation (absent from the defended version), the LSASS process access events that represent the core detection target, the Microsoft debugging DLL loads by `xordump.exe`, and the creation of the XOR-encoded dump file. The XOR-encoded output file pattern (`-x 0x41`) is a specific behavioral indicator not present in generic LSASS dumping tools, adding detection value beyond what applies to generic dump utilities. This dataset is useful for building detections that catch both the tool's command-line signature and its DLL loading behavior.

## Detection Opportunities Present in This Data

1. Sysmon EID 10 with `TargetImage` matching `lsass.exe` and `SourceImage` being an executable from `C:\Windows\Temp\` or another user-writable path — dropping and executing dump tools from temp directories is highly anomalous.

2. Sysmon EID 1 showing a process created from `C:\Windows\Temp\xordump.exe` with command-line arguments containing `-out` and `-x` flags — the specific argument structure is detectable.

3. Sysmon EID 7 (Image Load) showing `dbghelp.dll` or `dbgcore.dll` being loaded by a non-standard process (not `procdump.exe`, `WerFault.exe`, or other known debuggers) — these DLLs loaded by an unsigned or unknown executable from a temp directory are high-fidelity.

4. Sysmon EID 11 with `TargetFilename` containing `.dmp` in `C:\Windows\Temp\` where the creating process is not a known debugging utility — the file extension and path combination is detectable.

5. PowerShell EID 4104 script blocks containing the string `xordump.exe` combined with `-x` (XOR key flag) — this specific tool and flag combination is a precise behavioral indicator.

6. Security EID 4688 showing `powershell.exe` executing a command line that includes a binary path under `C:\Windows\Temp\` with dump-file output arguments — lateral tool transfer followed by in-place execution from temp directories is a common attacker pattern worth detecting broadly.
