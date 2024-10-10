package main

import (
	"fmt"
	"github.com/D3Ext/Hooka/pkg/hooka"
	"log"
	"time"
)

func main() {
  fmt.Println("[*] Enabling BlockDLLs on current process...")
	err := hooka.BlockDLLs()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("[+] Now non-Microsoft signed DLLs can't inject into this process")

  fmt.Println("[*] Creating a notepad.exe process with BlockDLLs enabled...")
  err = hooka.CreateProcessBlockDLLs("C:\\Windows\\System32\\notepad.exe")
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println("[+] Process created successfully")

	time.Sleep(1000 * time.Second)

  // Do some other stuff
}
