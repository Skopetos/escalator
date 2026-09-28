#!/usr/bin/env bash
#
# enum.sh - bash fallback for `escalator enum`.
#
# A dependency-free Linux privilege-escalation enumerator. Use it when you
# cannot drop the Go binary on the target (no scp, locked-down box, etc.) - it
# relies only on coreutils that ship with any Linux system.
#
# Usage:  ./enum.sh            # print findings to the terminal
#         ./enum.sh | tee out  # and save a copy
#
# Authorised lab / own-systems use only.

set -u

# ---- colours (disabled when not a terminal or NO_COLOR is set) --------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    R=$'\e[1;31m'; G=$'\e[1;32m'; C=$'\e[1;36m'; D=$'\e[2m'; Z=$'\e[0m'
else
    R=''; G=''; C=''; D=''; Z=''
fi
hit()  { printf '  %s[!]%s %s\n' "$R" "$Z" "$*"; }   # likely privesc vector
info() { printf '  %s[+]%s %s\n' "$G" "$Z" "$*"; }   # informational
note() { printf '  %s[*]%s %s\n' "$C" "$Z" "$*"; }   # worth a look
plain(){ printf '      %s%s%s\n' "$D" "$*" "$Z"; }
section() {
    printf '\n%s==================== %s ====================%s\n' "$C" "$1" "$Z"
}

# Binaries that give a root shell when runnable via sudo (GTFOBins subset).
GTFO="python python2 python2.7 python3 python3.5 python3.6 perl ruby lua vim vi \
nano less more man awk find nmap tcpdump tar zip env bash sh ftp git ed mysql cp"

# ---- system -----------------------------------------------------------------
section "SYSTEM INFORMATION"
info "OS: $( (. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}") )"
info "Kernel: $(uname -a)"
info "Hostname: $(hostname)"
case "$(uname -r)" in
    2.*|3.*|4.4*) hit "old kernel ($(uname -r)) - check searchsploit for local root exploits" ;;
esac

# ---- user context -----------------------------------------------------------
section "USER & GROUP CONTEXT"
info "Running as: $(id)"
for grp in $(id -Gn 2>/dev/null); do
    case "$grp" in
        docker) hit "member of 'docker' - trivially root via a mounted container" ;;
        lxd|lxc) hit "member of '$grp' - root via a privileged container image" ;;
        disk)   hit "member of 'disk' - raw block-device access = read/write any file" ;;
        sudo|admin) note "member of '$grp' - check 'sudo -l'" ;;
    esac
done
note "interactive accounts:"
awk -F: '($3>=1000 || $3==0) && $7 !~ /nologin|false/ {printf "        %s uid=%s shell=%s\n",$1,$3,$7}' /etc/passwd

# ---- sudo -------------------------------------------------------------------
section "SUDO PRIVILEGES"
sudo_out="$(sudo -n -l 2>&1)"
if echo "$sudo_out" | grep -q "password is required\|may not run sudo"; then
    note "sudo -l needs a password or is not permitted; run it manually if you have one"
else
    echo "$sudo_out" | sed 's/^/      /'
    for b in $GTFO; do
        if echo "$sudo_out" | grep -qE "NOPASSWD.*/${b}(,| |\$)|/${b}\$"; then
            hit "sudo can run '$b' - shell escape available (see GTFOBins)"
        fi
    done
    echo "$sudo_out" | grep -q "(ALL : ALL) ALL\|(ALL) ALL" && \
        hit "sudo grants ALL - run 'sudo -i' for root"
fi

# ---- SUID / SGID ------------------------------------------------------------
section "SUID BINARIES"
find / -xdev -perm -4000 -type f 2>/dev/null | while read -r f; do
    case "$(basename "$f")" in
        find|nmap|vim|less|more|awk|python*|perl|env|tar|bash|cp|nano)
            hit "$f (SUID) - possible shell escape (GTFOBins)" ;;
        ping|ping6|fusermount|mount|umount|su|gpasswd|chfn|passwd|chsh|newgrp|sudo|pkexec|at|newgidmap|newuidmap|dmcrypt-get-device|lxc-user-nic|snap-confine|dbus-daemon-launch-helper|polkit-agent-helper-1|ssh-keysign)
            plain "$f" ;;
        *) hit "$f (SUID) - non-standard, investigate" ;;
    esac
done

section "SGID BINARIES"
find / -xdev -perm -2000 -type f 2>/dev/null | sed 's/^/      /'

# ---- capabilities -----------------------------------------------------------
section "FILE CAPABILITIES"
if command -v getcap >/dev/null 2>&1; then
    getcap -r /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /opt /home 2>/dev/null \
        | sed 's/^/      /' || note "none found"
else
    note "getcap not available; skipping"
fi

# ---- cron -------------------------------------------------------------------
section "SCHEDULED JOBS (CRON)"
grep -rvE '^\s*#|^\s*$' /etc/crontab /etc/cron.d/ 2>/dev/null | sed 's/^/      /'
for f in /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/*; do
    [ -w "$f" ] && [ "$(id -u)" -ne 0 ] && hit "$f is writable by you - inject a command to run as its owner"
done

# ---- writable / sensitive ---------------------------------------------------
section "WORLD-WRITABLE & SENSITIVE FILES"
for p in /etc/passwd /etc/shadow /etc/sudoers; do
    [ -w "$p" ] && [ "$(id -u)" -ne 0 ] && hit "$p is writable - instant root"
done
note "world-writable, root-owned files (first 25):"
find / -xdev -user root -perm -0002 -type f 2>/dev/null | head -25 | sed 's/^/      /'

# ---- credential hunting -----------------------------------------------------
section "CREDENTIAL HUNTING"
for f in /home/important.txt /.runme.sh /home/*/user.txt /home/*/.bash_history; do
    [ -r "$f" ] || continue
    note "readable: $f"
    grep -HniE 'pass|pwd|secret|token|key|[a-f0-9]{32}' "$f" 2>/dev/null | head -5 | sed 's/^/      /'
done

# ---- PATH -------------------------------------------------------------------
section "PATH & ENVIRONMENT"
info "PATH=$PATH"
IFS=: read -ra dirs <<<"$PATH"
for d in "${dirs[@]}"; do
    [ "$d" = "." ] && hit "PATH contains '.' - vulnerable to binary hijacking"
    [ -w "$d" ] && [ "$(id -u)" -ne 0 ] && hit "PATH dir $d is writable - plant a binary to hijack commands"
done

section "DONE"
