# T1090.001-3: Internal Proxy — portproxy reg key

## Technique Context

T1090.001 Internal Proxy is a command-and-control technique where adversaries use legitimate operating system features to proxy network traffic through compromised systems. The Windows `netsh interface portproxy` command is particularly valuable to attackers because it creates persistent port forwarding rules that survive reboots and operate at the network stack level. This technique allows adversaries to pivot through networks, bypass network segmentation, tunnel traffic through trusted systems, and establish covert channels. Detection teams focus on monitoring netsh portproxy activity, registry modifications under the PortProxy service key, and unusual network listening patterns on non-standard ports.

## What This Dataset Contains

This dataset captures a successful execution of the netsh portproxy technique. The process chain begins with PowerShell (PID 21512) spawning another PowerShell instance (PID 20528) with the command line `"powershell.exe" & {netsh interface portproxy add v4tov4 listenport=1337 connectport=1337 connectaddress=127.0.0.1}`. This second PowerShell process then spawns netsh.exe (PID 21772) with the full command `"C:\Windows\system32\netsh.exe" interface portproxy add v4tov4 listenport=1337 connectport=1337 connectaddress=127.0.0.1`.

The critical detection artifact is present in Sysmon EID 13 (Registry value set): `HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp\*/1337` with the value `127.0.0.1/1337`. This registry modification creates a persistent port forwarding rule redirecting traffic from port 1337 to localhost:1337. The Security channel captures the process creation events with full command lines via EID 4688 events, showing the complete attack chain. Multiple Sysmon EID 10 (Process accessed) events show PowerShell processes accessing the spawned child processes, indicating normal PowerShell execution behavior.

## What This Dataset Does Not Contain

The dataset does not contain network connection events (Sysmon EID 3) showing the actual port being bound or traffic being forwarded through the proxy. While Sysmon network connection logging is enabled, no connections were established during this brief test execution. There are no Sysmon EID 22 (DNS query) events, indicating no DNS resolution activity. The dataset lacks any Windows Filtering Platform events that would show the low-level network stack changes. Additionally, there are no failure indicators — the technique executed successfully without Defender interference, as evidenced by the clean exit status (0x0) in Security EID 4689 events.

## Assessment

This dataset provides excellent detection engineering value for the T1090.001 technique. The combination of Security 4688 events with full command lines and Sysmon 13 registry monitoring captures both the execution attempt and the persistent configuration change. The registry modification under `HKLM\System\CurrentControlSet\Services\PortProxy` is a high-fidelity indicator that's difficult for attackers to avoid when using this technique. The process creation telemetry shows clear parent-child relationships and suspicious command-line patterns involving netsh portproxy operations. While network telemetry would enhance the dataset, the existing process and registry monitoring provides sufficient coverage for building robust detections.

## Detection Opportunities Present in This Data

1. **Registry monitoring for PortProxy service modifications** - Alert on Sysmon EID 13 events targeting `HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\*` registry paths, which indicate persistent port forwarding rule creation.

2. **Command-line detection for netsh portproxy operations** - Monitor Security EID 4688 and Sysmon EID 1 events where the command line contains `netsh` combined with `interface portproxy add`, indicating proxy configuration attempts.

3. **Process chain analysis for PowerShell-to-netsh execution** - Detect PowerShell processes (parent) spawning netsh.exe (child) with portproxy-related arguments, indicating scripted proxy setup.

4. **Anomalous netsh usage detection** - Flag netsh.exe executions with `portproxy` arguments, especially when spawned by interpreters like PowerShell, cmd.exe, or script hosts rather than administrative tools.

5. **Registry value pattern matching** - Create signatures for registry values under PortProxy keys that contain IP addresses and port numbers in the format `IP/PORT`, indicating active forwarding rules.

6. **Privilege escalation correlation** - Correlate Security EID 4703 (token right adjusted) events showing elevated privileges with subsequent netsh portproxy activity, indicating potential abuse of administrative access.
