# T1485-5: ESXi — Delete VM Snapshots

## Technique Context

T1485 (Data Destruction) against VMware ESXi hypervisors targets VM snapshots specifically to eliminate recovery checkpoints before ransomware deployment or after data exfiltration. In a typical ransomware playbook, attackers gain access to the ESXi management plane, remove all snapshots, then encrypt the flat VMDK files. Without snapshots, victims cannot roll back to a pre-attack state. The detection community focuses on SSH-based ESXi commands (`vim-cmd vmsvc/snapshot.removeall`) and on the Windows-side tooling used to reach ESXi, particularly PuTTY's `plink.exe` for non-interactive SSH.

## What This Dataset Contains

The test uses `plink.exe` (PuTTY Link) from the ART ExternalPayloads directory to SSH into an ESXi host and run a shell loop that removes all snapshots from every VM. Security EID 4688 captures the full command line:

```
"cmd.exe" /c echo "" | "C:\AtomicRedTeam\atomics\..\ExternalPayloads\plink.exe"
  -batch "atomic.local" -ssh -l root -pw "password"
  "for i in `vim-cmd vmsvc/getallvms | awk 'NR>1 {print $1}'`;
   do vim-cmd vmsvc/snapshot.removeall $i & done"
```

This is high-fidelity telemetry: the target hostname, credentials (`-l root -pw "password"`), and the exact ESXi commands are visible in the 4688 command line. Sysmon EID 1 captures the cmd.exe process creation tagged as `technique_id=T1059.003`. Security EID 4689 shows cmd.exe exiting with `0x1` (the plink command likely failed because the target ESXi host `atomic.local` did not exist in this environment) and an inner cmd.exe exiting `0xFF`.

The PowerShell channel contains only test framework boilerplate. Sysmon EID 17 records the PowerShell host pipe, and EID 11 records PowerShell startup profile writes.

## What This Dataset Does Not Contain

`plink.exe` itself does not appear as a Sysmon EID 1 event — sysmon-modular include-mode filtering does not match it, so only cmd.exe (the wrapper) is captured in Sysmon. There is no network connection telemetry to port 22 because the connection failed (no reachable ESXi host); a successful execution would produce a Sysmon EID 3 event showing an outbound SSH connection. No ESXi-side telemetry is present — this dataset only covers the Windows operator workstation, not the hypervisor being attacked. The actual snapshot deletion activity on the ESXi host is entirely outside this dataset's scope.

## Assessment

The dataset's primary value is the EID 4688 command line, which contains the full attack payload including target, credentials, and ESXi vim-cmd invocation. This is exactly what analysts need to write detections for plink-based ESXi targeting. The failed execution (no live ESXi target) means no network connection events were generated, which limits network-based detection development. Augmenting with a live ESXi target would add Sysmon EID 3 (TCP/22 to ESXi IP) as a third detection layer.

## Detection Opportunities Present in This Data

1. **Security EID 4688**: Process creation for `plink.exe` with `-ssh` and `vim-cmd vmsvc/snapshot.removeall` in the command line — direct detection of ESXi snapshot deletion via SSH.
2. **Security EID 4688**: `plink.exe` invoked with cleartext credentials via `-pw` flag — credential exposure in command line audit logs.
3. **Security EID 4688**: `plink.exe` launched from an ART-like path (`AtomicRedTeam\atomics\...\ExternalPayloads\`) — non-standard parent path for SSH tooling.
4. **Sysmon EID 1**: `cmd.exe` spawned from `powershell.exe` with command line containing `vim-cmd` or `snapshot.removeall` — ESXi management commands appearing on a Windows workstation.
5. **Security EID 4688**: Any use of `plink.exe -batch` in an enterprise environment where PuTTY is not an approved tool — policy-based detection.
6. **Security EID 4689 + 4688 correlation**: Short-lived cmd.exe wrapping plink with non-zero exit code — detection of failed but attempted ESXi targeting.
