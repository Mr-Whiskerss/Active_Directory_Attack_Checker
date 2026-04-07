# AD Attack Path Checker

An automated Active Directory security assessment tool. Runs 84 checks across attack surface, privilege escalation paths, credential exposure, and AD misconfiguration — collecting raw evidence per check and generating a timestamped HTML report.

---

## Legal Disclaimer

> This tool is intended for **authorised security assessments only**.  
> You must have **explicit written permission** from the system owner before running this tool against any environment.  
> Unauthorised use against systems you do not own or have permission to test is **illegal** and may result in criminal prosecution.  
> The author accepts no liability for misuse of this tool.

---

## Features

- 84 automated checks across signing, relay, Kerberos, ADCS, delegation, credential exposure, privilege escalation, and network services
- Pass-the-Hash support (`-H`) across all NXC, impacket, and certipy calls
- Raw command output captured as evidence per check
- Colour-coded terminal output for fast triage
- Timestamped HTML report with per-category grouping and collapsible evidence blocks
- Skippable checks for targeted or time-limited assessments
- Subnet-wide host enumeration for broader coverage

---

## Requirements

### Python
- Python 3.8+

### Required Tools

| Tool | Install |
|------|---------|
| [NetExec (nxc)](https://github.com/Pennyw0rth/NetExec) | `pip install netexec` |

### Optional Tools (extend coverage)

| Tool | Install | Used For |
|------|---------|----------|
| [Certipy-AD](https://github.com/ly4k/Certipy) | `pip install certipy-ad` | ADCS ESC1–ESC13 enumeration, Shadow Credentials |
| [Impacket](https://github.com/fortra/impacket) | `pip install impacket` | Delegation, SPNs, Kerberos |
| [Kerbrute](https://github.com/ropnop/kerbrute) | Download binary | User enumeration without creds |
| [Nmap](https://nmap.org) | `apt install nmap` | IPMI, SMTP relay, SNMP, port checks |
| [ldapsearch](https://www.openldap.org) | `apt install ldap-utils` | LDAP null bind |
| [rpcclient](https://www.samba.org) | `apt install samba` | Domain trust fallback |
| [redis-cli](https://redis.io) | `apt install redis-tools` | Redis unauthenticated check |

---

## Installation

```bash
git clone https://github.com/Mr-Whiskerss/ad-attack-checker
cd ad-attack-checker
chmod +x ad_attack_checker.py
```

No external Python dependencies — the tool relies on the tools listed above being available in `$PATH`.

---

## Usage

### Password authentication

```bash
python3 ad_attack_checker.py -dc <DC_IP> -u <username> -p <password> -d <domain>
```

### Pass-the-Hash (PtH)

```bash
# Bare NT hash (32 hex chars)
python3 ad_attack_checker.py -dc <DC_IP> -u <username> -H <NT_HASH> -d <domain>

# LMHASH:NTHASH format
python3 ad_attack_checker.py -dc <DC_IP> -u <username> -H <NT_HASH> -d <domain>
```

### Full options

```bash
python3 ad_attack_checker.py \
  -dc 10.0.0.1 \
  -u 'john.smith' \
  -p 'Password123!' \
  -d corp.local \
  -s 10.0.0.0/24 \
  -o ./loot \
  --skip zerologon ms17010 spray
```

### Arguments

| Flag | Required | Description | Example |
|------|----------|-------------|---------|
| `-dc` | ✅ | Domain controller IP address | `-dc 10.0.0.1` |
| `-u` | ✅ | Username | `-u 'john.smith'` |
| `-p` | ✅ / `-H` | Password | `-p 'Password123!'` |
| `-H` | ✅ / `-p` | NT hash for Pass-the-Hash | `-H ...` |
| `-d` | ✅ | Domain FQDN | `-d corp.local` |
| `-s` | ❌ | Subnet for host-wide checks | `-s 10.0.0.0/24` |
| `-o` | ❌ | Output directory (default: `./loot`) | `-o ./loot` |
| `--skip` | ❌ | Space-separated list of checks to skip | `--skip zerologon ms17010` |
| `--wordlist` | ❌ | Wordlist path for kerbrute user enum | `--wordlist /opt/users.txt` |

> Either `-p` or `-H` must be supplied. Supplying neither will exit with an error.

---

## Checks Performed

### Signing & Relay

| Skip Key | Check | Technique |
|----------|-------|-----------|
| `smb` | SMB Signing | NTLM relay prerequisite |
| `ldapsign` | LDAP Signing + Channel Binding | LDAP relay prerequisite |
| `llmnr` | LLMNR / NBT-NS (wcc module) | Responder poisoning prerequisite |

### Machine Accounts

| Skip Key | Check | Technique |
|----------|-------|-----------|
| `maq` | MachineAccountQuota | noPac / RBCD prerequisite |
| `nopac` | noPac CVE-2021-42278/42287 | PAC size comparison |
| `prewin2000` | Pre-Windows 2000 Compatible Access | Predictable computer password |

### Coercion

| Skip Key | Check | Technique |
|----------|-------|-----------|
| `coercion` | coerce_plus (PetitPotam, DFSCoerce, MSEven, PrinterBug) | NTLM/Kerberos coercion |
| `webdav` | WebClient / WebDAV | HTTP coercion bypass (mitm6) |
| `spooler` | Print Spooler | PrinterBug prerequisite |

### ADCS

| Skip Key | Check | Technique |
|----------|-------|-----------|
| `ldaps` | LDAPS Port 636 | Shadow credentials prerequisite |
| `adcs` | ADCS Discovery + Certipy ESC1–ESC13 + ESC8 | AD CS attack paths |

### Kerberos

| Skip Key | Check | Technique |
|----------|-------|-----------|
| `kerberoast` | Kerberoasting | SPN ticket extraction |
| `asrep` | AS-REP Roasting | Pre-auth disabled accounts |
| `userenum` | User Enumeration (kerbrute, no creds) | KDC username validation |
| `dupespns` | Duplicate SPNs | Relay / impersonation path |
| `krbtgt` | krbtgt Password Age | Golden ticket window |

### Critical CVEs

| Skip Key | Check | CVE |
|----------|-------|-----|
| `zerologon` | Zerologon | CVE-2020-1472 |
| `ms17010` | EternalBlue | MS17-010 |
| `exchange` | Exchange Detection | ProxyLogon/ProxyShell indicator |
| `privexchange` | PrivExchange / Exchange WriteDACL | Exchange → DA path |

### Delegation

| Skip Key | Check | Technique |
|----------|-------|-----------|
| `delegation` | Unconstrained + Constrained Delegation | TGT capture / impersonation |

### Credential Exposure

| Skip Key | Check | Technique |
|----------|-------|-----------|
| `passpol` | Domain Password Policy | Weak policy identification |
| `fgpp` | Fine-Grained Password Policies | PSO misconfiguration |
| `gpp` | GPP Passwords (cpassword) | SYSVOL cleartext creds |
| `gppautologin` | GPP Autologin | SYSVOL autologin creds |
| `laps` | LAPS Deployment + Readability | Local admin password exposure |
| `descriptions` | Passwords in User Descriptions | AD attribute credential leakage |
| `cleartextldap` | Cleartext LDAP Passwords | userPassword / unixUserPassword |
| `passnoreq` | Password Not Required flag | PASSWD_NOTREQD UAC bit |
| `passneverexpires` | Password Never Expires | Stale credential exposure |
| `gmsa` | gMSA Password Readability | msDS-ManagedPassword access |
| `spray` | Password Spray (seasonal candidates) | Credential guessing |
| `useqpass` | User = Password | Common weak credential pattern |
| `samlsa` | SAM / LSA Dump | Local credential extraction |
| `lsappl` | LSA Protection (RunAsPPL) | LSASS protection status |
| `dpapi` | DPAPI Masterkey Discovery | Offline blob decryption |
| `keepass` | KeePass Database Discovery + Trigger | .kdbx extraction |
| `veeam` | Veeam Backup Credentials | Plaintext backup job creds |
| `mremoteng` | mRemoteNG Stored Credentials | Weak AES confCons.xml |
| `wifi` | WiFi Saved Passwords | PSK reuse identification |

### Privileged Groups

| Skip Key | Check | Technique |
|----------|-------|-----------|
| `admincount` | AdminCount=1 Users | SDProp-protected account audit |
| `privgroups` | Privileged Group Membership | DA/EA/Schema/Account Operators |
| `dnsadmins` | DnsAdmins Group | DLL injection via DNS service |
| `backupops` | Backup Operators | NTDS.dit backup path |
| `sidhistory` | SID History | Cross-domain escalation persistence |
| `adminsdh` | AdminSDHolder ACL | Protected object ACE persistence |
| `guest` | Guest Account | Disabled status check |

### ACL / GPO

| Skip Key | Check | Technique |
|----------|-------|-----------|
| `dacl` | DACL Abuse — DCSync rights on domain root | ACE-based privilege escalation |
| `gpo` | GPO Write Permissions (basic) | GPO-based code execution |

### Network & Services

| Skip Key | Check | Technique |
|----------|-------|-----------|
| `ipv6` | IPv6 Enabled | mitm6 prerequisite |
| `winrm` | WinRM Access | Lateral movement path |
| `mssql` | MSSQL Instances | Linked server / xp_cmdshell |
| `rdpnla` | RDP NLA | NLA disabled = pre-auth exposure |
| `smbv1` | SMBv1 Enabled | EternalBlue / relay prerequisite |
| `snmp` | SNMP Community Strings | Default community exposure |
| `nullbind` | LDAP Null Bind | Unauthenticated enumeration |
| `nfs` | NFS Exports | World-readable mount exposure |
| `ipmi` | IPMI / BMC (port 623) | BMC credential exposure |
| `wsus` | WSUS Misconfiguration | HTTP WSUS → malicious update |
| `shares` | SMB Share Enumeration | Readable/writable shares |
| `spider` | Share Spider (keyword matching) | Sensitive file discovery |
| `rodc` | RODC Password Replication Policy | Cached credential exposure |

### Exposed Services

| Skip Key | Check | Technique |
|----------|-------|-----------|
| `smtp` | SMTP Open Relay | Mail relay abuse |
| `redis` | Redis Unauthenticated | No-auth remote access |
| `elastic` | Elasticsearch Unauthenticated | No-auth data access |
| `jenkins` | Jenkins / Tomcat Default Creds | Default credential access |
| `mssqllinked` | MSSQL Linked Servers | Cross-server privilege escalation |

### AD Intelligence

| Skip Key | Check | Technique |
|----------|-------|-----------|
| `trusts` | Domain Trusts | Cross-domain escalation paths |
| `azuread` | Azure AD Connect (MSOL) | DCSync via MSOL_ account |
| `bloodhound` | BloodHound Collection | Full AD attack graph |
| `avedr` | AV/EDR Detection | Evasion targeting |
| `aie` | AlwaysInstallElevated | MSI-based local privesc |
| `localadmin` | Local Admin Discovery | Lateral movement targets |

### PrivEsc — AD

| Skip Key | Check | Technique |
|----------|-------|-----------|
| `rbcd` | Resource-Based Constrained Delegation | msDS-AllowedToActOnBehalfOfOtherIdentity write |
| `shadowcreds` | Shadow Credentials | msDS-KeyCredentialLink write → PKINIT |
| `dcsync` | DCSync Rights (Non-Standard) | GetChangesAll on non-DA/EA accounts |
| `gpoabuse` | GPO Write Abuse (Scoped) | CreateChild/GenericWrite on GPO containers |
| `badsuccessor` | BadSuccessor | Delegated OU admin → Domain Admin |
| `ntlmv1` | NTLMv1 Accepted | RC4 downgrade → crack.sh NTLM cracking |
| `timeroast` | Timeroasting | Weak computer account RC4 key extraction |

### PrivEsc — Local

| Skip Key | Check | Technique |
|----------|-------|-----------|
| `unquotedsvc` | Unquoted Service Paths | Binary planting in intermediate path |
| `seimpers` | Dangerous Token Privileges | SeImpersonate → Potato / SeDebug → dump |
| `autologon` | Autologon Registry Credentials | DefaultPassword in Winlogon key |

---

## Output

The tool generates a timestamped HTML report saved to the output directory:

```
./loot/ad_attack_check_20260401_120000.html
```

The report includes:
- Executive summary with vuln/safe/unknown counts
- Results overview table (all checks, category, status, recommendation)
- Detailed findings grouped by category with collapsible raw evidence blocks
- Colour-coded cards (🔴 vulnerable, 🟢 safe, 🟡 unknown)

---

## Skip Examples

```bash
# Skip potentially destructive or noisy checks
python3 ad_attack_checker.py -dc 10.0.0.1 -u user -p pass -d corp.local \
  --skip zerologon ms17010 spray useqpass samlsa

# Quick-win focused run — signing, kerberos, ADCS, privesc only
python3 ad_attack_checker.py -dc 10.0.0.1 -u user -p pass -d corp.local \
  --skip snmp nfs redis elastic smtp ipmi rodc rdpnla smbv1 nullbind \
         mssql mssqllinked jenkins bloodhound

# Pass-the-Hash run with subnet coverage
python3 ad_attack_checker.py \
  -dc 10.0.0.1 \
  -u 'svc_account' \
  -H '<NT_HASH> \
  -d corp.local \
  -s 10.0.0.0/24 \
  -o ./loot
```

---

## Author

[Mr-Whiskerss](https://github.com/Mr-Whiskerss)
