# T1105-11: Ingress Tool Transfer — OSTAP Worming Activity

## Technique Context

T1105 Ingress Tool Transfer represents attackers' need to bring external tools and files into a compromised environment to enable further malicious activities. This technique is fundamental to most attack chains, as initial access rarely provides all the capabilities needed for objectives like privilege escalation, lateral movement, or data exfiltration. Attackers commonly use legitimate system utilities, network protocols, or cloud services to transfer tools while blending with normal traffic.

The OSTAP malware family is particularly notorious for its worm-like propagation capabilities across network shares and removable drives. OSTAP typically uses JavaScript droppers to establish persistence and download additional payloads. The detection community focuses on identifying unusual file transfers to network locations, script-based file operations, and processes accessing network shares in unexpected patterns.

## What This Dataset Contains

This dataset captures a simulated OSTAP worming activity that demonstrates file transfer and execution across network shares. The core attack chain shows:

PowerShell spawning CMD with a complex command line: `"cmd.exe" /c pushd \\localhost\C$ & echo var fileObject = WScript.createobject("Scripting.FileSystemObject");var newfile = fileObject.CreateTextFile("AtomicTestFileT1105.js", true);newfile.WriteLine("This is an atomic red team test file for T1105. It simulates how OSTap worms accross network shares and drives.");newfile.Close(); > AtomicTestT1105.js & CScript.exe AtomicTestT1105.js //E:JScript & del AtomicTestT1105.js /Q >nul 2>&1 & del AtomicTestFileT1105.js /Q >nul 2>&1 & popd`

Security event 4688 captures the CMD execution, followed by CScript.exe launching with `CScript.exe AtomicTestT1105.js //E:JScript`. Sysmon EID 1 events show the process creation chain: PowerShell → CMD → CScript.exe, with CScript.exe executing from the Z:\ drive (mapped network share). Sysmon EID 7 events reveal AMSI and Windows Defender components loading into CScript.exe, indicating real-time protection was active during execution.

The dataset shows CScript.exe exiting with status 0x1 (failure), suggesting Windows Defender may have blocked the JavaScript execution or the file operations failed due to security controls.

## What This Dataset Does Not Contain

The dataset lacks evidence of successful file creation or network file operations. There are no Sysmon EID 11 file creation events for the JavaScript files that should have been created on the network share. The absence of successful script execution telemetry suggests Windows Defender blocked the malicious JavaScript before it could complete its file operations.

Network connection events (Sysmon EID 3) are missing, which would normally show the establishment of SMB connections to \\localhost\C$. File access events and detailed error information about why CScript.exe failed are also absent. The PowerShell script block logging only contains test framework boilerplate rather than the actual attack commands.

## Assessment

This dataset provides excellent process execution telemetry but limited evidence of the file transfer aspects that define T1105. The process creation events clearly show the attack chain and command-line evidence, making it valuable for detecting OSTAP-style JavaScript droppers and CScript.exe abuse. However, the apparent blocking by Windows Defender means the actual ingress tool transfer components are not well-represented.

The Security 4688 events provide complete command-line visibility that would be crucial for detecting this technique in environments where Sysmon isn't available. The Sysmon process access events show PowerShell interacting with spawned processes, which could indicate process monitoring or injection attempts.

## Detection Opportunities Present in This Data

1. **JavaScript File Creation and Execution Pattern**: Command lines containing JavaScript file creation followed immediately by CScript.exe execution with the same filename indicate potential malware dropping behavior.

2. **Network Share Access with Script Execution**: The combination of `pushd \\localhost\C$` or similar UNC paths with script execution suggests worm-like propagation attempts.

3. **CScript.exe with Inline JavaScript Operations**: Command lines showing CScript.exe executing files created through echo redirection, especially with FileSystemObject operations, indicate potential malicious script deployment.

4. **Rapid File Creation and Deletion**: The pattern of creating temporary JavaScript files, executing them, then immediately deleting both the script and its created files suggests evasion behavior.

5. **Process Chain PowerShell → CMD → CScript.exe**: This specific execution chain, especially when CMD contains complex JavaScript generation logic, indicates potential script-based ingress tool transfer.

6. **AMSI Loading into Scripting Engines**: Sysmon EID 7 events showing AMSI.dll loading into CScript.exe can indicate script execution attempts that may trigger behavioral analysis.
