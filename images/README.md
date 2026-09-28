# Proof screenshots

Drop the screenshots captured from the booted lab VM here, using the filenames
referenced in the main [`../README.md`](../README.md) proof section:

- `01-discovery.png`   — host/port scan showing the VM IP and ports 21/22/80
- `02-ftp-upload.png`  — anonymous FTP login and `put cmd.php`
- `03-rce-www-data.png`— `curl .../cmd.php?c=id` returning `uid=33(www-data)`
- `04-runme-cred.png`  — `/.runme.sh` output with the `shrek:MD5` line
- `05-ssh-shrek.png`   — SSH as `shrek` and `sudo -l`
- `06-root-flag.png`   — root shell (`uid=0`) and `cat /root/root.txt`

The most important one is `06-root-flag.png` (proof of root + flag).
