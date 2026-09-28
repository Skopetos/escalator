package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// ANSI colour helpers. Colour is disabled automatically when output is not a
// terminal or when the NO_COLOR environment variable is set, so the tool stays
// readable when its output is piped into a file or another program.
var useColor = detectColor()

func detectColor() bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func paint(code, s string) string {
	if !useColor {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func bold(s string) string   { return paint("1", s) }
func red(s string) string    { return paint("1;31", s) }
func green(s string) string  { return paint("1;32", s) }
func yellow(s string) string { return paint("1;33", s) }
func blue(s string) string   { return paint("1;34", s) }
func cyan(s string) string   { return paint("1;36", s) }
func dim(s string) string    { return paint("2", s) }

// report collects findings and writes them to one or more sinks (stdout and,
// optionally, a file). Severity markers keep the output skimmable:
//
//	[+] good / informational
//	[*] neutral finding worth a look
//	[!] likely privilege-escalation vector
type report struct {
	w io.Writer
}

func newReport(extra io.Writer) *report {
	if extra == nil {
		return &report{w: os.Stdout}
	}
	return &report{w: io.MultiWriter(os.Stdout, extra)}
}

func (r *report) line(s string) { fmt.Fprintln(r.w, s) }

func (r *report) section(title string) {
	bar := strings.Repeat("═", 62)
	r.line("")
	r.line(cyan("╔" + bar + "╗"))
	r.line(cyan("║ ") + bold(pad(title, 60)) + cyan(" ║"))
	r.line(cyan("╚" + bar + "╝"))
}

func (r *report) info(format string, a ...any) {
	r.line("  " + green("[+] ") + fmt.Sprintf(format, a...))
}

func (r *report) note(format string, a ...any) {
	r.line("  " + blue("[*] ") + fmt.Sprintf(format, a...))
}

func (r *report) hit(format string, a ...any) {
	r.line("  " + red("[!] ") + fmt.Sprintf(format, a...))
}

func (r *report) plain(format string, a ...any) {
	r.line("      " + dim(fmt.Sprintf(format, a...)))
}

func pad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}
