# T1027.013-1: Encrypted/Encoded File — Decode Eicar File and Write to File

## Technique Context

T1027.013 Encrypted/Encoded File covers scenarios where adversaries encode, encrypt, or otherwise transform files and payloads to conceal their content from security tools that rely on signature matching or content inspection. Base64 encoding is the most common approach because it is built into PowerShell, Python, and most scripting environments — no external tools are required. The pattern is straightforward: a malicious payload (shellcode, a second-stage binary, a configuration file, or a command string) is Base64-encoded and stored as a string constant in the script or in a remote resource. At execution time, the script decodes it and writes it to disk or directly executes it in memory.

This test uses the EICAR antivirus test string as the simulated payload. The EICAR string (`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`) is a benign string that most antivirus products recognize and flag as a test file. By Base64-encoding it and decoding at runtime, the test simulates a real attacker's workflow of transporting encoded payloads and materializing them on disk. The Base64-encoded value `WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=` carries no detectable malicious content until decoded.

## What This Dataset Contains

The dataset spans a few seconds (23:04:45–23:04:54 UTC on 2026-03-14) and totals 129 events across three channels.

The complete technique execution is captured in Sysmon EID 1 and Security EID 4688. The technique PowerShell process (PID 6584) is spawned with the full command line:

```
"powershell.exe" & {$encodedString = "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo="
$bytes = [System.Convert]::FromBase64String($encodedString)
$decodedString = [System.Text.Encoding]::UTF8.GetString($bytes)

#write the decoded eicar string to file
$decodedString | Out-File T1027.013_decodedEicar.txt}
```

The `#write the decoded eicar string to file` comment in the command line is an ART artifact but illustrates that in real attacks, similar descriptive comments sometimes appear in staged scripts. The output file path `T1027.013_decodedEicar.txt` is a relative path, which combined with the `CurrentDirectory: C:\Windows\TEMP\` from the process create event, resolves to `C:\Windows\Temp\T1027.013_decodedEicar.txt`.

The defended version's analysis confirmed that Sysmon EID 11 captures the file creation of `C:\Windows\Temp\T1027.013_decodedEicar.txt`. The full 29-event Sysmon dataset contains 2 EID 11 events; the 20-sample set did not include them, but they are present in the data files. Similarly, the defended version confirmed that EID 4103 module logging captures the `Out-File` invocation with the decoded EICAR string as a parameter value.

Sysmon EID 3 captures two mDNS queries from svchost.exe (192.168.4.22 → port 5353 IPv4, and fe80::..:fd54:9588 → port 5353 IPv6) — standard local service discovery activity unrelated to the technique.

Sysmon EID 7 documents the technique PowerShell process loading standard .NET CLR libraries and the Defender monitoring DLLs. No AV quarantine or detection event is generated for the EICAR string written to disk in this undefended run.

Event counts are similar to the defended version (37 Sysmon, 10 Security) — this technique is not blocked by Defender in either configuration, so the difference is minimal.

## What This Dataset Does Not Contain

The Sysmon EID 11 file creation events for `T1027.013_decodedEicar.txt` are not in the 20-event sample set but exist in the full dataset. No Windows Defender quarantine or alert events are present, even though the EICAR string is a known test file — this appears to be consistent behavior in this environment. The PowerShell channel's EID 4104 20-sample set contains only test framework boilerplate; the actual decode script block and Out-File invocation details are in the full 96-event dataset. There are no network events associated with the decode operation itself.

## Assessment

This dataset demonstrates the clean end-to-end Base64 decode-and-write workflow. The command line in Sysmon EID 1 and Security EID 4688 contains both the encoded payload and the decoding logic, making it a useful training example for detection rules that look for `FromBase64String` combined with file write operations. The full dataset's EID 4103 captures the decoded EICAR string as a parameter value, demonstrating that module logging can expose the decoded content of encoded payloads without requiring behavioral execution monitoring. This dataset is well-suited for building and validating detections that target Base64 decode-and-stage patterns in PowerShell.

## Detection Opportunities Present in This Data

1. **Sysmon EID 1 / EID 4688 — [System.Convert]::FromBase64String in command line**: The presence of `FromBase64String` in a PowerShell command line is a reliable indicator that a Base64 payload is being decoded. Combined with `Out-File` or similar write cmdlets in the same command, it indicates decode-to-disk activity.

2. **Sysmon EID 1 / EID 4688 — Base64 string matching**: The encoded string `WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=` is a fixed, known indicator for the EICAR test payload specifically. More broadly, detecting long Base64 strings (40+ characters of `[A-Za-z0-9+/=]`) as command-line arguments is a heuristic for encoded payload detection.

3. **EID 4103 — Out-File parameter binding with decoded EICAR content**: Module logging captures `ParameterBinding(Out-File): name="InputObject"; value="X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"` — the decoded payload as plaintext. This is the definitive confirmation of what was written to disk, useful both for detection and for threat intelligence extraction.

4. **Sysmon EID 11 — file creation of decoded content from PowerShell in TEMP**: The file `T1027.013_decodedEicar.txt` (or any file written by a PowerShell process to `C:\Windows\Temp\` whose name contains a technique identifier or timestamp) is a file creation detection opportunity. Monitoring for file writes by PowerShell to temp directories following Base64 decode operations is a compound behavioral indicator.

5. **EID 4104 — script block containing FromBase64String + GetString + Out-File**: The script block pattern `[System.Convert]::FromBase64String($var)` → `[System.Text.Encoding]::UTF8.GetString($bytes)` → `Out-File` is a three-step decode-and-write sequence that appears in many real-world dropper scripts. Pattern matching this sequence in EID 4104 content would catch a broad class of similar payloads.
