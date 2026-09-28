package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// commonPorts is a compact top-ports list used for liveness sweeps and the
// default single-host scan. It is deliberately small so a /24 sweep finishes in
// seconds without raw sockets (a plain TCP connect is enough to prove a host is
// up and does not require root).
var commonPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
	993, 995, 1723, 3306, 3389, 5900, 8080, 8443,
}

var serviceNames = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
	110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
	443: "https", 445: "microsoft-ds", 993: "imaps", 995: "pop3s",
	1723: "pptp", 3306: "mysql", 3389: "ms-wbt", 5900: "vnc",
	8080: "http-alt", 8443: "https-alt",
}

func runDiscover(args []string) {
	fs := flag.NewFlagSet("discover", flag.ExitOnError)
	cidr := fs.String("cidr", "", "network to sweep in CIDR form (default: auto-detect local /24s)")
	target := fs.String("target", "", "scan a single host's ports instead of sweeping a network")
	portspec := fs.String("ports", "top", "ports to scan: \"top\", \"1-1024\", or a comma list like \"21,22,80\"")
	timeout := fs.Duration("timeout", 600*time.Millisecond, "per-connection timeout")
	workers := fs.Int("workers", 256, "number of concurrent connection workers")
	fs.Parse(args)

	rep := newReport(nil)

	if *target != "" {
		ports := parsePorts(*portspec)
		rep.section(fmt.Sprintf("Port scan: %s (%d ports)", *target, len(ports)))
		open := scanPorts(*target, ports, *timeout, *workers)
		if len(open) == 0 {
			rep.note("no open ports found (host may be down or filtered)")
			return
		}
		for _, p := range open {
			svc := serviceNames[p]
			if svc == "" {
				svc = "unknown"
			}
			rep.info("%5d/tcp open  %s", p, svc)
		}
		return
	}

	cidrs := []string{}
	if *cidr != "" {
		cidrs = []string{*cidr}
	} else {
		cidrs = localCIDRs()
		if len(cidrs) == 0 {
			fmt.Fprintln(os.Stderr, "could not auto-detect a local network; pass -cidr")
			os.Exit(1)
		}
	}

	arp := readARP()
	for _, c := range cidrs {
		rep.section("Host sweep: " + c)
		hosts, err := expandCIDR(c)
		if err != nil {
			rep.note("skipping %s: %v", c, err)
			continue
		}
		live := sweep(hosts, commonPorts, *timeout, *workers)
		if len(live) == 0 {
			rep.note("no live hosts detected on %s", c)
			continue
		}
		for _, h := range live {
			mac := arp[h.ip]
			extra := ""
			if mac != "" {
				extra = "  mac=" + mac
			}
			rep.info("%-15s up   ports: %s%s", h.ip, joinPorts(h.ports), extra)
		}
		rep.line("")
		rep.note("tip: pick the VM's IP above, then: escalator discover -target <ip> -ports 1-1024")
	}
}

type liveHost struct {
	ip    string
	ports []int
}

// sweep probes each host on a handful of common ports. A host that accepts a
// connection on any of them is considered up. This avoids ICMP (which needs
// elevated privileges) while still reliably finding a services-exposing VM.
func sweep(hosts []string, ports []int, timeout time.Duration, workers int) []liveHost {
	type job struct{ ip string }
	jobs := make(chan job)
	results := make(chan liveHost)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				var open []int
				for _, p := range ports {
					if dialOpen(j.ip, p, timeout) {
						open = append(open, p)
					}
				}
				if len(open) > 0 {
					results <- liveHost{ip: j.ip, ports: open}
				}
			}
		}()
	}

	go func() {
		for _, h := range hosts {
			jobs <- job{ip: h}
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	var live []liveHost
	for r := range results {
		live = append(live, r)
	}
	sort.Slice(live, func(i, j int) bool { return ipLess(live[i].ip, live[j].ip) })
	return live
}

// scanPorts scans one host across the supplied ports and returns the open ones.
func scanPorts(host string, ports []int, timeout time.Duration, workers int) []int {
	jobs := make(chan int)
	results := make(chan int)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				if dialOpen(host, p, timeout) {
					results <- p
				}
			}
		}()
	}
	go func() {
		for _, p := range ports {
			jobs <- p
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	var open []int
	for p := range results {
		open = append(open, p)
	}
	sort.Ints(open)
	return open
}

func dialOpen(host string, port int, timeout time.Duration) bool {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// localCIDRs returns the /24 networks of the machine's non-loopback IPv4
// interfaces, which is the usual place a host-only or bridged lab VM lives.
func localCIDRs() []string {
	var out []string
	seen := map[string]bool{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() {
			continue
		}
		ip4 := ipnet.IP.To4()
		if ip4 == nil {
			continue
		}
		c := fmt.Sprintf("%d.%d.%d.0/24", ip4[0], ip4[1], ip4[2])
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

func expandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var hosts []string
	for cur := ip.Mask(ipnet.Mask); ipnet.Contains(cur); inc(cur) {
		hosts = append(hosts, cur.String())
	}
	// Drop network and broadcast addresses for a /24-style range.
	if len(hosts) > 2 {
		hosts = hosts[1 : len(hosts)-1]
	}
	return hosts, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// readARP parses /proc/net/arp into an ip->mac map to enrich sweep output. It is
// best-effort: on platforms without that file the map is simply empty.
func readARP() map[string]string {
	out := map[string]string{}
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 4 && fields[3] != "00:00:00:00:00:00" {
			out[fields[0]] = fields[3]
		}
	}
	return out
}

func parsePorts(spec string) []int {
	spec = strings.TrimSpace(spec)
	switch spec {
	case "", "top":
		return commonPorts
	}
	if strings.Contains(spec, "-") {
		var lo, hi int
		if _, err := fmt.Sscanf(spec, "%d-%d", &lo, &hi); err == nil && lo >= 1 && hi >= lo {
			var ports []int
			for p := lo; p <= hi && p <= 65535; p++ {
				ports = append(ports, p)
			}
			return ports
		}
	}
	var ports []int
	for _, part := range strings.Split(spec, ",") {
		var p int
		if _, err := fmt.Sscanf(strings.TrimSpace(part), "%d", &p); err == nil {
			ports = append(ports, p)
		}
	}
	if len(ports) == 0 {
		return commonPorts
	}
	return ports
}

func joinPorts(ports []int) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = fmt.Sprintf("%d", p)
	}
	return strings.Join(parts, ",")
}

func ipLess(a, b string) bool {
	ipa, ipb := net.ParseIP(a).To4(), net.ParseIP(b).To4()
	if ipa == nil || ipb == nil {
		return a < b
	}
	for i := 0; i < 4; i++ {
		if ipa[i] != ipb[i] {
			return ipa[i] < ipb[i]
		}
	}
	return false
}
