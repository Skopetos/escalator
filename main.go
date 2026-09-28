// escalator is a small, dependency-free toolkit written for the "Escalator"
// privilege-escalation lab (Ubuntu 16.04 target VM). It bundles two helpers:
//
//	discover  - find the target on the network and map its open ports
//	enum      - enumerate a Linux host for local privilege-escalation vectors
//
// The tool performs *authorised* security testing only. It is meant to be run
// against the provided lab VM (or your own systems). See README.md for the full
// walkthrough of the intended attack path it was built to support.
package main

import (
	"fmt"
	"os"
)

const version = "1.0.0"

func usage() {
	fmt.Fprintf(os.Stderr, `escalator %s - privilege-escalation lab toolkit

Usage:
  escalator <command> [flags]

Commands:
  discover   Sweep a network for live hosts and scan a host's open ports
  enum       Enumerate the local system for privilege-escalation vectors
  version    Print version and exit
  help       Show this message

Run "escalator <command> -h" for command-specific flags.

Examples:
  escalator discover                      # auto-detect the local /24 and sweep it
  escalator discover -cidr 192.168.56.0/24
  escalator discover -target 192.168.56.101 -ports top
  escalator enum                          # full local enumeration (run on target)
  escalator enum -o findings.txt          # also save findings to a file
`, version)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "discover":
		runDiscover(os.Args[2:])
	case "enum":
		runEnum(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("escalator %s\n", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}
