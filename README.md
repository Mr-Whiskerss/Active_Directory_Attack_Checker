# AD Attack Path Checker

An automated Active Directory security assessment tool. Runs 83 checks across attack surface, privilege escalation paths, credential exposure, and AD misconfiguration — **in parallel** — capturing raw evidence per check and generating timestamped HTML and JSON reports.

Built to be plonk-and-go: point it at a DC and it runs a preflight, executes only the checks that fit your access (including a **credential-less null-session pass**), and sorts findings vuln-first.

---

## Legal Disclaimer

> This tool is intended for **authorised security assessments only**.  
> You must have **explicit written permission** from the system owner before running this tool against any environment.  
> Unauthorised use against systems you do not own or have permission to test is **illegal** and may result in criminal prosecution.  
> The author accepts no liability for misuse of this tool.

---

## Features

- **83 automated checks** across signing, relay, Kerberos, ADCS, delegation, credential exposure, privilege escalation, and network services
- **Concurrent execution** — checks run in a thread pool (`-j`, default 10), typically 5–10× faster than sequential. `-j 1` restores live sequential output
- **No-credential / null-session mode** (`--no-creds`) for the pre-access phase — auto-detects the domain from the DC banner and runs only the checks that work without creds
- **Tag-based selection** — run subsets by behaviour (`--tags` / `--skip-tags`), pick specific checks (`--only`), or list them all (`--list-checks`)
- **Preflight** — inventories tooling and validates credentials once, so a bad login or missing NetExec fails fast instead of 80+ times
- **Pass-the-Hash** (`-H`) across all NetExec, impacket, and certipy calls
- **Machine-readable JSON report** (`--json`) alongside the HTML, for diffing between runs and feeding pipelines
- Harvested loot (roast hashes, spray lists) written to the output directory at `0700` — not world-readable `/tmp`
- Reliable vuln / safe / unknown severity classification; raw command output captured as evidence per check
- Colour-coded terminal output; graceful `Ctrl-C` still writes a partial report
- Timestamped HTML report with per-category grouping and collapsible evidence blocks
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
git clone https://github.com/Mr-Whiskerss/Active_Directory_Attack_Checker
cd Active_Directory_Attack_Checker
chmod +x AD_Attack_Checker.py
```

No external Python dependencies — the tool relies on the tools listed above being available in `$PATH`.

---

## Usage

### Quick start (with creds)

```bash
python3 AD_Attack_Checker.py -dc <DC_IP> -u <username> -p <password> -d <domain>
```

### No credentials yet (null-session pass)

For the common internal drop — a Linux box on the network and no domain account.
Runs the credential-less check set; the domain is auto-detected from the DC's SMB banner.

```bash
python3 AD_Attack_Checker.py -dc <DC_IP> --no-creds
```

### Pass-the-Hash

```bash
python3 AD_Attack_Checker.py -dc <DC_IP> -u <username> -H <NT_HASH> -d <domain>
```

### Fast full sweep with JSON

```bash
python3 AD_Attack_Checker.py -dc 10.0.0.1 -u 'john.smith' -p 'Password123!' \
  -d corp.local -s 10.0.0.0/24 -o ./loot -j 12 --json
```

### Arguments

| Flag | Required | Description | Example |
|------|----------|-------------|---------|
| `-dc` | ✅ | Domain controller IP address | `-dc 10.0.0.1` |
| `-u` | ✅ ¹ | Username | `-u 'john.smith'` |
| `-p` / `-H` | ✅ ¹ | Password, or NT hash for Pass-the-Hash | `-p 'Passw0rd!'` |
| `-d` | ✅ ¹ | Domain FQDN (auto-detected in `--no-creds`) | `-d corp.local` |
| `-s` | ❌ | Subnet for host-wide checks | `-s 10.0.0.0/24` |
| `-o` | ❌ | Output directory (default: `./loot`) | `-o ./loot` |
| `--no-creds` | ❌ | Credential-less null-session pass (see below) | |
| `-j`, `--jobs` | ❌ | Parallel worker threads (default 10; `1` = sequential) | `-j 12` |
| `--only` | ❌ | Run ONLY these check keys | `--only smb adcs` |
| `--tags` | ❌ | Run only checks carrying any of these tags | `--tags quickwin` |
| `--skip` | ❌ | Skip these check keys | `--skip zerologon spray` |
| `--skip-tags` | ❌ | Skip checks carrying any of these tags | `--skip-tags noisy` |
| `--list-checks` | ❌ | Print all checks (key / category / tags) and exit | |
| `--json` | ❌ | Also write a machine-readable JSON report | |
| `--timeout-scale` | ❌ | Multiply every command timeout (slow/large estates) | `--timeout-scale 2` |
| `--wordlist` | ❌ | Username wordlist for kerbrute user enum | `--wordlist /opt/users.txt` |
| `--verbose` | ❌ | Print raw command output to the console | |
| `--force` | ❌ | Run even if preflight (tools/creds) fails | |

> ¹ `-u`, `-p`/`-H` and `-d` are required for an authenticated run. In `--no-creds`
> mode only `-dc` is required — username defaults to a null session and the domain
> is auto-detected from the DC banner.

---

## No-credential mode (`--no-creds`)

Triggered explicitly with `--no-creds`, or inferred automatically when you supply
no authentication material at all (just `-dc`).

- Runs a **null session** against the DC — no `-u`/`-p` needed.
- **Domain auto-detected** from the DC's SMB banner during preflight.
- Preflight skips credential validation and instead probes anonymously, reporting
  whether the null session is allowed or blocked by `RestrictAnonymous`.
- Automatically restricts the run to the **`unauth` check set** — the 15 checks that
  genuinely return data without credentials — so you don't fire 60+ authenticated
  checks that would only produce logon failures. Override with `--only` / `--tags`.

The `unauth` set reads status pre-authentication (SMB signing, SMBv1, RDP NLA from
the banner/handshake), exploits unauthenticated flaws by design (Zerologon,
MS17-010), or hits credential-free services (LDAP null-bind, LDAPS, user enum, SNMP,
NFS, IPMI, SMTP relay, Redis, Elasticsearch, Jenkins/Tomcat). Once you gain a
foothold, re-run with `-u user -p pass` for the full 83.

> On a hardened DC with `RestrictAnonymous` set, the null session is refused and the
> LDAP/SAMR-based checks come back blank — the banner-based and network/service checks
> carry that pass. Preflight tells you which situation you're in.

---

## Selecting checks (tags & filters)

Every check carries zero or more behavioural **tags**. Selection is additive-then-subtractive:
`--only` and `--tags` choose the pool, `--skip` and `--skip-tags` remove from it.

| Tag | Meaning |
|-----|---------|
| `unauth` | Returns data without domain credentials (drives `--no-creds`) |
| `quickwin` | High-signal findings worth running first |
| `noisy` | Louder / lockout- or alert-prone (spray, roasting, coercion, BloodHound) |
| `privesc` | Concrete privilege-escalation primitives |
| `host` | Benefits from a `-s` subnet (member hosts, not just the DC) |

```bash
# See every check, its category and tags
python3 AD_Attack_Checker.py --list-checks

# Quiet quick-wins only
python3 AD_Attack_Checker.py -dc 10.0.0.1 -u user -p pass -d corp.local --tags quickwin

# Low-and-slow: drop lockout/alert-prone checks and double timeouts
python3 AD_Attack_Checker.py -dc 10.0.0.1 -u user -p pass -d corp.local \
  --skip-tags noisy --timeout-scale 2

# Just two specific checks
python3 AD_Attack_Checker.py -dc 10.0.0.1 -u user -p pass -d corp.local --only smb adcs
```

---

## Checks Performed
## Checks Performed

### Signing & Relay

| Key | Check | Technique | Tags |
|----------|-------|-----------|-------|
| `smb` | SMB Signing | NTLM relay prerequisite | `quickwin`, `unauth` |
| `ldapsign` | LDAP Signing + Channel Binding | LDAP relay prerequisite | `quickwin` |
| `llmnr` | LLMNR / NBT-NS (wcc module) | Responder poisoning prerequisite | — |

### Machine Accounts

| Key | Check | Technique | Tags |
|----------|-------|-----------|-------|
| `maq` | MachineAccountQuota | noPac / RBCD prerequisite | `quickwin` |
| `nopac` | noPac CVE-2021-42278/42287 | PAC size comparison | — |
| `prewin2000` | Pre-Windows 2000 Compatible Access | Predictable computer password | — |

### Coercion

| Key | Check | Technique | Tags |
|----------|-------|-----------|-------|
| `coercion` | coerce_plus (PetitPotam, DFSCoerce, MSEven, PrinterBug) | NTLM/Kerberos coercion | `noisy` |
| `webdav` | WebClient / WebDAV | HTTP coercion bypass (mitm6) | `host` |
| `spooler` | Print Spooler | PrinterBug prerequisite | — |

### ADCS

| Key | Check | Technique | Tags |
|----------|-------|-----------|-------|
| `ldaps` | LDAPS Port 636 | Shadow credentials prerequisite | `unauth` |
| `adcs` | ADCS Discovery + Certipy ESC1–ESC13 + ESC8 | AD CS attack paths | `quickwin` |

### Kerberos

| Key | Check | Technique | Tags |
|----------|-------|-----------|-------|
| `kerberoast` | Kerberoasting | SPN ticket extraction | `quickwin` |
| `asrep` | AS-REP Roasting | Pre-auth disabled accounts | `quickwin` |
| `userenum` | User Enumeration (kerbrute, no creds) | KDC username validation | `noisy`, `unauth` |
| `dupespns` | Duplicate SPNs | Relay / impersonation path | — |
| `krbtgt` | krbtgt Password Age | Golden ticket window | — |

### Critical CVEs

| Key | Check | CVE | Tags |
|----------|-------|-----|-------|
| `zerologon` | Zerologon | CVE-2020-1472 | `noisy`, `quickwin`, `unauth` |
| `ms17010` | EternalBlue | MS17-010 | `unauth` |
| `exchange` | Exchange Detection | ProxyLogon/ProxyShell indicator | — |
| `privexchange` | PrivExchange / Exchange WriteDACL | Exchange → DA path | — |

### Delegation

| Key | Check | Technique | Tags |
|----------|-------|-----------|-------|
| `delegation` | Unconstrained + Constrained Delegation | TGT capture / impersonation | `quickwin` |

### Credential Exposure

| Key | Check | Technique | Tags |
|----------|-------|-----------|-------|
| `passpol` | Domain Password Policy | Weak policy identification | `quickwin` |
| `fgpp` | Fine-Grained Password Policies | PSO misconfiguration | — |
| `gpp` | GPP Passwords (cpassword) | SYSVOL cleartext creds | `quickwin` |
| `gppautologin` | GPP Autologin | SYSVOL autologin creds | — |
| `laps` | LAPS Deployment + Readability | Local admin password exposure | `quickwin` |
| `descriptions` | Passwords in User Descriptions | AD attribute credential leakage | — |
| `cleartextldap` | Cleartext LDAP Passwords | userPassword / unixUserPassword | — |
| `passnoreq` | Password Not Required flag | PASSWD_NOTREQD UAC bit | — |
| `passneverexpires` | Password Never Expires | Stale credential exposure | — |
| `gmsa` | gMSA Password Readability | msDS-ManagedPassword access | — |
| `spray` | Password Spray (seasonal candidates) | Credential guessing | `noisy` |
| `useqpass` | User = Password | Common weak credential pattern | `noisy` |
| `samlsa` | SAM / LSA Dump | Local credential extraction | `noisy` |
| `lsappl` | LSA Protection (RunAsPPL) | LSASS protection status | — |
| `dpapi` | DPAPI Masterkey Discovery | Offline blob decryption | `host` |
| `keepass` | KeePass Database Discovery + Trigger | .kdbx extraction | `host` |
| `veeam` | Veeam Backup Credentials | Plaintext backup job creds | `host` |
| `mremoteng` | mRemoteNG Stored Credentials | Weak AES confCons.xml | `host` |
| `wifi` | WiFi Saved Passwords | PSK reuse identification | `host` |

### Privileged Groups

| Key | Check | Technique | Tags |
|----------|-------|-----------|-------|
| `admincount` | AdminCount=1 Users | SDProp-protected account audit | — |
| `privgroups` | Privileged Group Membership | DA/EA/Schema/Account Operators | `quickwin` |
| `dnsadmins` | DnsAdmins Group | DLL injection via DNS service | — |
| `backupops` | Backup Operators | NTDS.dit backup path | — |
| `sidhistory` | SID History | Cross-domain escalation persistence | — |
| `adminsdh` | AdminSDHolder ACL | Protected object ACE persistence | — |
| `guest` | Guest Account | Disabled status check | — |

### ACL / GPO

| Key | Check | Technique | Tags |
|----------|-------|-----------|-------|
| `dacl` | DACL Abuse — DCSync rights on domain root | ACE-based privilege escalation | `privesc` |
| `gpo` | GPO Write Permissions (basic) | GPO-based code execution | `privesc` |

### Network & Services

| Key | Check | Technique | Tags |
|----------|-------|-----------|-------|
| `ipv6` | IPv6 Enabled | mitm6 prerequisite | `host` |
| `winrm` | WinRM Access | Lateral movement path | — |
| `mssql` | MSSQL Instances | Linked server / xp_cmdshell | `host` |
| `rdpnla` | RDP NLA | NLA disabled = pre-auth exposure | `unauth` |
| `smbv1` | SMBv1 Enabled | EternalBlue / relay prerequisite | `unauth` |
| `snmp` | SNMP Community Strings | Default community exposure | `host`, `unauth` |
| `nullbind` | LDAP Null Bind | Unauthenticated enumeration | `unauth` |
| `nfs` | NFS Exports | World-readable mount exposure | `host`, `unauth` |
| `ipmi` | IPMI / BMC (port 623) | BMC credential exposure | `host`, `unauth` |
| `wsus` | WSUS Misconfiguration | HTTP WSUS → malicious update | — |
| `shares` | SMB Share Enumeration | Readable/writable shares | `host` |
| `spider` | Share Spider (keyword matching) | Sensitive file discovery | `host`, `noisy` |
| `rodc` | RODC Password Replication Policy | Cached credential exposure | — |

### Exposed Services

| Key | Check | Technique | Tags |
|----------|-------|-----------|-------|
| `smtp` | SMTP Open Relay | Mail relay abuse | `host`, `unauth` |
| `redis` | Redis Unauthenticated | No-auth remote access | `host`, `unauth` |
| `elastic` | Elasticsearch Unauthenticated | No-auth data access | `unauth` |
| `jenkins` | Jenkins / Tomcat Default Creds | Default credential access | `host`, `unauth` |
| `mssqllinked` | MSSQL Linked Servers | Cross-server privilege escalation | `host` |

### AD Intelligence

| Key | Check | Technique | Tags |
|----------|-------|-----------|-------|
| `trusts` | Domain Trusts | Cross-domain escalation paths | — |
| `azuread` | Azure AD Connect (MSOL) | DCSync via MSOL_ account | — |
| `bloodhound` | BloodHound Collection | Full AD attack graph | `noisy` |
| `avedr` | AV/EDR Detection | Evasion targeting | — |
| `aie` | AlwaysInstallElevated | MSI-based local privesc | `privesc` |
| `localadmin` | Local Admin Discovery | Lateral movement targets | `host` |

### PrivEsc — AD

| Key | Check | Technique | Tags |
|----------|-------|-----------|-------|
| `rbcd` | Resource-Based Constrained Delegation | msDS-AllowedToActOnBehalfOfOtherIdentity write | `privesc` |
| `shadowcreds` | Shadow Credentials | msDS-KeyCredentialLink write → PKINIT | `privesc` |
| `dcsync` | DCSync Rights (Non-Standard) | GetChangesAll on non-DA/EA accounts | `privesc` |
| `gpoabuse` | GPO Write Abuse (Scoped) | CreateChild/GenericWrite on GPO containers | `privesc` |
| `badsuccessor` | BadSuccessor | Delegated OU admin → Domain Admin | `privesc` |
| `ntlmv1` | NTLMv1 Accepted | RC4 downgrade → crack.sh NTLM cracking | `host`, `privesc` |
| `timeroast` | Timeroasting | Weak computer account RC4 key extraction | `privesc` |

### PrivEsc — Local

| Key | Check | Technique | Tags |
|----------|-------|-----------|-------|
| `unquotedsvc` | Unquoted Service Paths | Binary planting in intermediate path | `host`, `privesc` |
| `seimpers` | Dangerous Token Privileges | SeImpersonate → Potato / SeDebug → dump | `privesc` |
| `autologon` | Autologon Registry Credentials | DefaultPassword in Winlogon key | `host`, `privesc` |

---

## Output

Reports are written to the output directory (`-o`, default `./loot`), timestamped:

```
./loot/ad_attack_check_20260401_120000.html
./loot/ad_attack_check_20260401_120000.json   # with --json
```

The **HTML report** includes:
- Executive summary with vuln/safe/unknown counts
- A run-metadata line: auth mode, checks run, commands issued, workers, elapsed time (and a PARTIAL flag if interrupted)
- Results overview table (all checks, category, status, recommendation)
- Detailed findings grouped by category with collapsible raw evidence blocks
- Colour-coded cards (🔴 vulnerable, 🟢 safe, 🟡 unknown)

The **JSON report** (`--json`) is the same data in a diffable, pipeline-friendly shape:
run metadata, summary counts, and a per-result array of `{check, category, status,
severity, recommendation, evidence}`. Useful for tracking a domain across retests.

**Loot** harvested during a run (Kerberoast/AS-REP hashes, spray candidate lists) is
written into the output directory with `0700` permissions — not world-readable `/tmp`.

---

## Examples

```bash
# Null-session pass — just dropped on a box, no creds yet
python3 AD_Attack_Checker.py -dc 10.0.0.1 --no-creds --json

# Skip lockout/alert-prone checks by tag
python3 AD_Attack_Checker.py -dc 10.0.0.1 -u user -p pass -d corp.local --skip-tags noisy

# Skip specific checks by key
python3 AD_Attack_Checker.py -dc 10.0.0.1 -u user -p pass -d corp.local \
  --skip zerologon ms17010 spray useqpass samlsa

# Quick-win focused run
python3 AD_Attack_Checker.py -dc 10.0.0.1 -u user -p pass -d corp.local --tags quickwin

# Pass-the-Hash with subnet coverage, 12 workers, JSON + HTML
python3 AD_Attack_Checker.py \
  -dc 10.0.0.1 \
  -u 'svc_account' \
  -H '<NT_HASH>' \
  -d corp.local \
  -s 10.0.0.0/24 \
  -o ./loot -j 12 --json
```

---

## Author

[Mr-Whiskerss](https://github.com/Mr-Whiskerss)
