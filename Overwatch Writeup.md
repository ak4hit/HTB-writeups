## Writeup
- [HackTheBox — Overwatch Writeup](https://medium.com/@ak4hit/hackthebox-overwatch-writeup-3bf7fdd2474f)

## Attack Path Summary
- Nmap → SMB (`software$`) → Decompile .NET → MSSQL creds
- MSSQL → Linked server `SQL07` → ADIDNS poisoning + Responder → `sqlmgmt` creds
- Evil-WinRM → User flag
- Chisel tunnel → SOAP `KillProcess` injection → Root flag